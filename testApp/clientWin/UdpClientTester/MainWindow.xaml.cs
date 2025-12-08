using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace UdpClientTester
{
    /// <summary>
    /// UDP 서버 부하 테스트 도구
    /// </summary>
    public partial class MainWindow : Window
    {
        private UdpClient? _udpClient;
        private CancellationTokenSource? _cts;
        private volatile bool _isRunning;
        private volatile bool _isClosing;
        
        // 최대 로그 항목 수 (메모리 누수 방지)
        private const int MaxLogEntries = 10000;
        
        // UI 업데이트 쓰로틀링
        private const int UiUpdateIntervalMs = 50;
        private volatile bool _uiUpdatePending;
        
        // 통계 변수
        private long _sentCount;
        private long _receivedCount;
        private long _failedCount;
        private long _mismatchCount;
        private long _totalRttTicks;
        private int _packetIndex;

        // 대기 중인 패킷 추적 (패킷 해시 -> 전송 정보)
        private readonly ConcurrentDictionary<string, PendingPacket> _pendingPackets = new();

        // 결과 컬렉션
        private readonly ObservableCollection<TestResult> _results = new();
        
        // 배치 처리를 위한 결과 큐
        private readonly ConcurrentQueue<TestResult> _pendingResults = new();

        public MainWindow()
        {
            InitializeComponent();
            lvResults.ItemsSource = _results;
        }

        private async void btnStart_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning || _isClosing)
                return;
                
            if (!ValidateInputs())
                return;

            Task? receiveTask = null;
            Task? timeoutCheckTask = null;
            Task? uiUpdateTask = null;

            try
            {
                // UI 상태 변경
                SetRunningState(true);
                ResetStatistics();

                string serverAddress = txtServerAddress.Text.Trim();
                int port = int.Parse(txtPort.Text);
                int packetSize = int.Parse(txtPacketSize.Text);
                int sendCount = int.Parse(txtSendCount.Text);
                int interval = int.Parse(txtInterval.Text);
                int timeout = int.Parse(txtTimeout.Text);
                bool continuous = chkContinuous.IsChecked == true;

                _cts = new CancellationTokenSource();
                _udpClient = new UdpClient();
                _udpClient.Connect(serverAddress, port);

                UpdateStatus($"서버 {serverAddress}:{port}에 연결됨. 테스트 시작...");

                // 수신 태스크와 전송 태스크를 병렬로 실행
                receiveTask = ReceivePacketsAsync(_cts.Token);
                timeoutCheckTask = CheckTimeoutsAsync(timeout, _cts.Token);
                uiUpdateTask = BatchUpdateUiAsync(_cts.Token);
                
                var sendTask = SendPacketsAsync(packetSize, sendCount, interval, continuous, _cts.Token);

                await sendTask;
                
                // 전송 완료 후 마지막 패킷의 타임아웃까지 대기
                try
                {
                    await Task.Delay(timeout + 100, _cts.Token);
                }
                catch (OperationCanceledException) { }
                
                _cts.Cancel();

                // 모든 태스크 완료 대기
                await Task.WhenAll(
                    SafeAwaitTask(receiveTask),
                    SafeAwaitTask(timeoutCheckTask),
                    SafeAwaitTask(uiUpdateTask)
                );

                // 남은 결과 모두 처리
                FlushAllPendingResults();

                UpdateStatus($"테스트 완료! 총 {_sentCount}개 전송, {_receivedCount}개 수신, {_failedCount}개 타임아웃, {_mismatchCount}개 불일치");
            }
            catch (OperationCanceledException)
            {
                UpdateStatus("테스트가 중지되었습니다.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"오류 발생: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
                UpdateStatus($"오류: {ex.Message}");
            }
            finally
            {
                SetRunningState(false);
                CleanupUdpClient();
            }
        }

        private static async Task SafeAwaitTask(Task? task)
        {
            if (task == null) return;
            
            try
            {
                await task;
            }
            catch (OperationCanceledException)
            {
                // 정상적인 취소
            }
            catch (ObjectDisposedException)
            {
                // 이미 dispose된 객체
            }
            catch (Exception)
            {
                // 기타 예외도 안전하게 처리
            }
        }

        private async Task SendPacketsAsync(int packetSize, int sendCount, int interval, bool continuous, CancellationToken ct)
        {
            int iteration = 0;

            do
            {
                for (int i = 0; i < sendCount && !ct.IsCancellationRequested; i++)
                {
                    await SendPacketAsync(packetSize, ct);
                    
                    if (interval > 0)
                        await Task.Delay(interval, ct);
                }
                iteration++;
                
                if (continuous && !ct.IsCancellationRequested)
                {
                    UpdateStatus($"연속 모드: {iteration}번째 사이클 완료. 계속 진행 중...");
                }
            }
            while (continuous && !ct.IsCancellationRequested);
        }

        private async Task SendPacketAsync(int packetSize, CancellationToken ct)
        {
            int currentIndex = Interlocked.Increment(ref _packetIndex);
            var udpClient = _udpClient;
            
            if (udpClient == null || _isClosing)
                return;

            try
            {
                // 랜덤 패킷 생성
                byte[] packetData = GenerateRandomPacket(packetSize);
                string packetHash = Convert.ToBase64String(SHA256.HashData(packetData));
                string packetPreview = BitConverter.ToString(packetData.Take(Math.Min(16, packetData.Length)).ToArray());

                // 대기 목록에 추가
                var pendingPacket = new PendingPacket
                {
                    Index = currentIndex,
                    PacketHash = packetHash,
                    PacketPreview = packetPreview,
                    SendTimeTicks = Stopwatch.GetTimestamp()
                };
                _pendingPackets[packetHash] = pendingPacket;

                // 전송
                await udpClient.SendAsync(packetData, ct);
                
                Interlocked.Increment(ref _sentCount);
                RequestUiUpdate();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (ObjectDisposedException)
            {
                // 클라이언트가 이미 dispose됨
            }
            catch (Exception ex)
            {
                EnqueueResult(new TestResult
                {
                    Index = currentIndex,
                    SendTime = DateTime.Now.ToString("HH:mm:ss.fff"),
                    ReceiveTime = "-",
                    RoundTripTime = "-",
                    IsMatch = "-",
                    Status = $"전송 오류: {ex.Message}",
                    PacketPreview = "-"
                });

                Interlocked.Increment(ref _failedCount);
                RequestUiUpdate();
            }
        }

        private async Task ReceivePacketsAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && !_isClosing)
            {
                var udpClient = _udpClient;
                if (udpClient == null)
                    break;
                    
                try
                {
                    var udpResult = await udpClient.ReceiveAsync(ct);
                    var receiveTimeTicks = Stopwatch.GetTimestamp();
                    var receiveTime = DateTime.Now;
                    
                    // 수신된 패킷의 해시 계산
                    string receivedHash = Convert.ToBase64String(SHA256.HashData(udpResult.Buffer));
                    
                    // 대기 목록에서 일치하는 패킷 찾기
                    if (_pendingPackets.TryRemove(receivedHash, out var pendingPacket))
                    {
                        // 일치하는 패킷 찾음
                        long elapsedTicks = receiveTimeTicks - pendingPacket.SendTimeTicks;
                        double rtt = (double)elapsedTicks / Stopwatch.Frequency * 1000.0;

                        EnqueueResult(new TestResult
                        {
                            Index = pendingPacket.Index,
                            SendTime = pendingPacket.SendTimeFormatted,
                            ReceiveTime = receiveTime.ToString("HH:mm:ss.fff"),
                            RoundTripTime = rtt.ToString("F2"),
                            IsMatch = "일치",
                            Status = "성공",
                            PacketPreview = pendingPacket.PacketPreview
                        });

                        Interlocked.Increment(ref _receivedCount);
                        Interlocked.Add(ref _totalRttTicks, elapsedTicks);
                        RequestUiUpdate();
                    }
                    else
                    {
                        // 일치하는 패킷을 찾지 못함
                        string unknownPreview = BitConverter.ToString(udpResult.Buffer.Take(Math.Min(16, udpResult.Buffer.Length)).ToArray());
                        
                        EnqueueResult(new TestResult
                        {
                            Index = 0,
                            SendTime = "-",
                            ReceiveTime = receiveTime.ToString("HH:mm:ss.fff"),
                            RoundTripTime = "-",
                            IsMatch = "불일치",
                            Status = "알 수 없는 패킷",
                            PacketPreview = unknownPreview
                        });

                        Interlocked.Increment(ref _mismatchCount);
                        RequestUiUpdate();
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException)
                {
                    // 네트워크 오류 - 계속 시도
                }
            }
        }

        private async Task CheckTimeoutsAsync(int timeout, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && !_isClosing)
            {
                try
                {
                    await Task.Delay(100, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                var nowTicks = Stopwatch.GetTimestamp();
                var timeoutTicks = (long)(timeout / 1000.0 * Stopwatch.Frequency);
                
                var expiredPackets = _pendingPackets
                    .Where(p => (nowTicks - p.Value.SendTimeTicks) > timeoutTicks)
                    .ToList();

                foreach (var expired in expiredPackets)
                {
                    if (_pendingPackets.TryRemove(expired.Key, out var pendingPacket))
                    {
                        EnqueueResult(new TestResult
                        {
                            Index = pendingPacket.Index,
                            SendTime = pendingPacket.SendTimeFormatted,
                            ReceiveTime = "-",
                            RoundTripTime = "-",
                            IsMatch = "-",
                            Status = "타임아웃",
                            PacketPreview = pendingPacket.PacketPreview
                        });

                        Interlocked.Increment(ref _failedCount);
                        RequestUiUpdate();
                    }
                }
            }
        }

        private async Task BatchUpdateUiAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && !_isClosing)
            {
                try
                {
                    await Task.Delay(UiUpdateIntervalMs, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (_uiUpdatePending)
                {
                    _uiUpdatePending = false;
                    FlushPendingResults();
                    UpdateStatisticsDisplay();
                }
            }
        }

        private void EnqueueResult(TestResult result)
        {
            _pendingResults.Enqueue(result);
        }

        private void RequestUiUpdate()
        {
            _uiUpdatePending = true;
        }

        private void FlushPendingResults()
        {
            if (_isClosing) return;
            
            Dispatcher.BeginInvoke(() =>
            {
                int count = 0;
                while (_pendingResults.TryDequeue(out var result) && count < 100)
                {
                    // 최대 로그 수 제한 - 효율적인 제거
                    if (_results.Count >= MaxLogEntries)
                    {
                        // 한 번에 10%를 제거하여 성능 개선
                        int removeCount = MaxLogEntries / 10;
                        for (int i = 0; i < removeCount && _results.Count > 0; i++)
                        {
                            _results.RemoveAt(0);
                        }
                    }
                    
                    _results.Add(result);
                    count++;
                }

                if (_results.Count > 0)
                {
                    lvResults.ScrollIntoView(_results[^1]);
                }
            });
        }

        private void FlushAllPendingResults()
        {
            if (_isClosing) return;
            
            Dispatcher.BeginInvoke(() =>
            {
                while (_pendingResults.TryDequeue(out var result))
                {
                    if (_results.Count >= MaxLogEntries)
                    {
                        int removeCount = MaxLogEntries / 10;
                        for (int i = 0; i < removeCount && _results.Count > 0; i++)
                        {
                            _results.RemoveAt(0);
                        }
                    }
                    
                    _results.Add(result);
                }

                if (_results.Count > 0)
                {
                    lvResults.ScrollIntoView(_results[^1]);
                }
                
                UpdateStatisticsDisplay();
            });
        }

        private void UpdateStatisticsDisplay()
        {
            if (_isClosing) return;
            
            Dispatcher.BeginInvoke(() =>
            {
                long receivedCount = Interlocked.Read(ref _receivedCount);
                long totalRttTicks = Interlocked.Read(ref _totalRttTicks);
                long sentCount = Interlocked.Read(ref _sentCount);
                long failedCount = Interlocked.Read(ref _failedCount);

                txtSentCount.Text = sentCount.ToString();
                txtReceivedCount.Text = receivedCount.ToString();
                txtFailedCount.Text = failedCount.ToString();
                
                double avgRtt = receivedCount > 0 
                    ? (double)totalRttTicks / receivedCount / Stopwatch.Frequency * 1000.0
                    : 0;
                txtAvgRtt.Text = avgRtt.ToString("F2");

                double successRate = sentCount > 0 ? (receivedCount * 100.0 / sentCount) : 0;
                txtSuccessRate.Text = successRate.ToString("F2");
            });
        }

        private static byte[] GenerateRandomPacket(int size)
        {
            byte[] data = new byte[size];
            RandomNumberGenerator.Fill(data);
            return data;
        }

        private void btnStop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            UpdateStatus("테스트 중지 요청됨...");
        }

        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning)
            {
                MessageBox.Show("테스트 중에는 로그를 지울 수 없습니다.", "알림", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            
            _results.Clear();
            while (_pendingResults.TryDequeue(out _)) { }
            ResetStatistics();
            UpdateStatus("로그 및 통계 초기화됨");
        }

        private bool ValidateInputs()
        {
            if (string.IsNullOrWhiteSpace(txtServerAddress.Text))
            {
                MessageBox.Show("서버 주소를 입력하세요.", "입력 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!int.TryParse(txtPort.Text, out int port) || port < 1 || port > 65535)
            {
                MessageBox.Show("유효한 포트 번호(1-65535)를 입력하세요.", "입력 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!int.TryParse(txtPacketSize.Text, out int packetSize) || packetSize < 1 || packetSize > 65507)
            {
                MessageBox.Show("유효한 패킷 크기(1-65507)를 입력하세요.", "입력 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!int.TryParse(txtSendCount.Text, out int sendCount) || sendCount < 1)
            {
                MessageBox.Show("유효한 전송 횟수(1 이상)를 입력하세요.", "입력 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!int.TryParse(txtInterval.Text, out int interval) || interval < 0)
            {
                MessageBox.Show("유효한 전송 간격(0 이상)을 입력하세요.", "입력 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!int.TryParse(txtTimeout.Text, out int timeout) || timeout < 1)
            {
                MessageBox.Show("유효한 타임아웃(1 이상)을 입력하세요.", "입력 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            return true;
        }

        private void SetRunningState(bool running)
        {
            _isRunning = running;
            Dispatcher.BeginInvoke(() =>
            {
                btnStart.IsEnabled = !running;
                btnStop.IsEnabled = running;
                btnClear.IsEnabled = !running;
                txtServerAddress.IsEnabled = !running;
                txtPort.IsEnabled = !running;
                txtPacketSize.IsEnabled = !running;
                txtSendCount.IsEnabled = !running;
                txtInterval.IsEnabled = !running;
                txtTimeout.IsEnabled = !running;
                chkContinuous.IsEnabled = !running;
            });
        }

        private void ResetStatistics()
        {
            Interlocked.Exchange(ref _sentCount, 0);
            Interlocked.Exchange(ref _receivedCount, 0);
            Interlocked.Exchange(ref _failedCount, 0);
            Interlocked.Exchange(ref _mismatchCount, 0);
            Interlocked.Exchange(ref _totalRttTicks, 0);
            Interlocked.Exchange(ref _packetIndex, 0);
            
            _pendingPackets.Clear();
            _uiUpdatePending = false;
            
            Dispatcher.BeginInvoke(() =>
            {
                txtSentCount.Text = "0";
                txtReceivedCount.Text = "0";
                txtFailedCount.Text = "0";
                txtAvgRtt.Text = "0.00";
                txtSuccessRate.Text = "0.00";
            });
        }

        private void UpdateStatus(string message)
        {
            if (_isClosing) return;
            Dispatcher.BeginInvoke(() => txtStatus.Text = message);
        }

        private void CleanupUdpClient()
        {
            var udpClient = Interlocked.Exchange(ref _udpClient, null);
            try
            {
                udpClient?.Close();
                udpClient?.Dispose();
            }
            catch { }

            var cts = Interlocked.Exchange(ref _cts, null);
            try
            {
                cts?.Dispose();
            }
            catch { }

            _pendingPackets.Clear();
        }

        protected override void OnClosed(EventArgs e)
        {
            _isClosing = true;
            
            // 취소 요청
            var cts = _cts;
            try
            {
                cts?.Cancel();
            }
            catch { }
            
            // 리소스 정리
            CleanupUdpClient();
            
            // 큐 비우기
            while (_pendingResults.TryDequeue(out _)) { }
            
            base.OnClosed(e);
        }
    }

    /// <summary>
    /// 대기 중인 패킷 정보
    /// </summary>
    public class PendingPacket
    {
        public int Index { get; set; }
        public string PacketHash { get; set; } = string.Empty;
        public string PacketPreview { get; set; } = string.Empty;
        public long SendTimeTicks { get; set; }
        
        public string SendTimeFormatted => DateTime.Now.ToString("HH:mm:ss.fff");
    }

    /// <summary>
    /// 테스트 결과 데이터 클래스
    /// </summary>
    public class TestResult
    {
        public int Index { get; set; }
        public string SendTime { get; set; } = string.Empty;
        public string ReceiveTime { get; set; } = string.Empty;
        public string RoundTripTime { get; set; } = string.Empty;
        public string IsMatch { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string PacketPreview { get; set; } = string.Empty;
    }
}