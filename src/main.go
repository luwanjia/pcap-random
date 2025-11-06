package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// 初始化随机数生成器（兼容 Go 1.16+）
var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// packetData 存储数据包的原始信息和修改后的信息
type packetData struct {
	originalData []byte               // 原始字节数据（未修改时直接写入）
	captureInfo  gopacket.CaptureInfo // 抓包元信息
	modified     bool                 // 是否被修改
	modifiedData []byte               // 修改后的字节数据（修改时写入）
}

// generateRandomIP 生成合法的随机单播IPv4地址（排除特殊地址段）
func generateRandomIP() net.IP {
	for {
		parts := []byte{
			byte(rng.Intn(253) + 1), // 1-253
			byte(rng.Intn(254)),     // 0-253
			byte(rng.Intn(254)),
			byte(rng.Intn(254)),
		}
		ip := net.IPv4(parts[0], parts[1], parts[2], parts[3])

		// 排除特殊地址段
		if parts[0] >= 224 && parts[0] <= 239 { // 组播
			continue
		}
		if parts[0] == 127 { // 回环
			continue
		}
		if parts[0] == 10 { // 10.0.0.0/8
			continue
		}
		if parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31 { // 172.16.0.0/12
			continue
		}
		if parts[0] == 192 && parts[1] == 168 { // 192.168.0.0/16
			continue
		}

		return ip
	}
}

// generateRandomIPv6 生成合法的随机单播IPv6地址（排除特殊地址段）
func generateRandomIPv6() net.IP {
	for {
		// 生成16字节（8个16位段）的IPv6地址
		ipBytes := make([]byte, 16)
		_, err := rng.Read(ipBytes)
		if err != nil {
			continue // 生成失败重试
		}
		ip := net.IP(ipBytes)

		// 排除特殊地址段（不依赖废弃方法）
		switch {
		case ip.IsMulticast(): // 组播地址（ff00::/8）
			continue
		case ip.IsLoopback(): // 环回地址（::1/128）
			continue
		case ip.IsLinkLocalUnicast(): // 链路本地地址（fe80::/10）
			continue
		case ip[0] == 0xfe && ip[1] == 0xc0: // 站点本地地址（fec0::/10，已弃用）
			continue
		case ip[0] == 0xfc || ip[0] == 0xfd: // 私有地址（fc00::/7）
			continue
		}

		return ip
	}
}

// ipPair 表示源IP-目的IP对（用于统计频率）
type ipPair [2]string

// analyzeIPMappings 分析IPv4/IPv6流量，分别生成IP映射表（客户端-服务器方向）
func analyzeIPMappings(packets []gopacket.Packet) (ipv4Map, ipv6Map map[string]net.IP) {
	// 初始化统计map
	ipv4PairCount := make(map[ipPair]int)
	ipv6PairCount := make(map[ipPair]int)

	// 遍历数据包，分别统计IPv4/IPv6的IP对频率
	for _, pkt := range packets {
		// 处理IPv4
		if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			src := ip4.SrcIP.String()
			dst := ip4.DstIP.String()
			pair := ipPair{src, dst}
			ipv4PairCount[pair]++
			reversePair := ipPair{dst, src}
			if _, ok := ipv4PairCount[reversePair]; !ok {
				ipv4PairCount[reversePair] = 0
			}
		}

		// 处理IPv6
		if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			src := ip6.SrcIP.String()
			dst := ip6.DstIP.String()
			pair := ipPair{src, dst}
			ipv6PairCount[pair]++
			reversePair := ipPair{dst, src}
			if _, ok := ipv6PairCount[reversePair]; !ok {
				ipv6PairCount[reversePair] = 0
			}
		}
	}

	// 生成IPv4映射表
	ipv4Map = generateIPMap(ipv4PairCount, "IPv4")
	// 生成IPv6映射表
	ipv6Map = generateIPMap(ipv6PairCount, "IPv6")

	return ipv4Map, ipv6Map
}

// generateIPMap 根据IP对统计结果，生成单个协议（IPv4/IPv6）的IP映射表
func generateIPMap(pairCount map[ipPair]int, proto string) map[string]net.IP {
	if len(pairCount) == 0 {
		return nil
	}

	// 找到频率最高的主会话
	var mainPair ipPair
	maxCount := -1
	for pair, count := range pairCount {
		if count > maxCount {
			maxCount = count
			mainPair = pair
		}
	}

	// 确定客户端-服务器方向
	forwardCount := pairCount[mainPair]
	reversePair := ipPair{mainPair[1], mainPair[0]}
	reverseCount := pairCount[reversePair]

	var clientIP, serverIP string
	if reverseCount > forwardCount {
		clientIP = mainPair[1]
		serverIP = mainPair[0]
	} else {
		clientIP = mainPair[0]
		serverIP = mainPair[1]
	}

	// 打印会话信息
	fmt.Printf("  Detected %s primary session: %s (client) -> %s (server)\n", proto, clientIP, serverIP)
	fmt.Printf("  %s Forward packets: %d, Reverse packets: %d\n", proto, forwardCount, reverseCount)

	// 生成随机IP映射（根据协议类型选择生成函数）
	var newClientIP, newServerIP net.IP
	if proto == "IPv4" {
		newClientIP = generateRandomIP()
		newServerIP = generateRandomIP()
	} else {
		newClientIP = generateRandomIPv6()
		newServerIP = generateRandomIPv6()
	}

	return map[string]net.IP{
		clientIP: newClientIP,
		serverIP: newServerIP,
	}
}

// readPCAP 读取PCAP文件，返回解析后的数据包、原始字节数据、链路层类型
func readPCAP(filePath string) ([]gopacket.Packet, []packetData, layers.LinkType, error) {
	// 使用 pcapgo 读取PCAP（纯Go，无C依赖）
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, layers.LinkTypeEthernet, fmt.Errorf("open pcap file failed: %w", err)
	}
	defer f.Close()

	// 自动检测PCAP格式（支持pcap和pcapng）
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, nil, layers.LinkTypeEthernet, fmt.Errorf("create pcap reader failed: %w", err)
	}

	// 获取链路层类型
	linkType := layers.LinkType(reader.LinkType())

	var packets []gopacket.Packet
	var packetDatas []packetData

	for {
		// 读取单个数据包的原始字节和元信息
		originalData, ci, err := reader.ReadPacketData()
		if err != nil {
			break // 读取完毕或出错
		}

		// 解析数据包（强制解码所有层）
		pkt := gopacket.NewPacket(
			originalData,
			linkType,
			gopacket.DecodeOptions{NoCopy: true, Lazy: false, SkipDecodeRecovery: true},
		)

		// 存储原始数据和元信息
		packetDatas = append(packetDatas, packetData{
			originalData: originalData,
			captureInfo:  ci,
			modified:     false, // 初始为未修改
		})

		packets = append(packets, pkt)
	}

	return packets, packetDatas, linkType, nil
}

// writePCAP 写入PCAP文件（区分修改包和原始包）
func writePCAP(filePath string, packetDatas []packetData, linkType layers.LinkType) error {
	// 创建输出目录
	outputDir := filepath.Dir(filePath)
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("create output dir failed: %w", err)
		}
	}

	// 创建输出文件
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create output file failed: %w", err)
	}
	defer f.Close()

	// 创建PCAP写入器（纯Go，支持pcap格式）
	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, linkType); err != nil {
		return fmt.Errorf("write pcap header failed: %w", err)
	}

	// 遍历所有数据包，分别处理
	for _, pd := range packetDatas {
		if pd.modified {
			// 处理修改后的数据包：写入修改后的字节
			if err := writer.WritePacket(pd.captureInfo, pd.modifiedData); err != nil {
				return fmt.Errorf("write modified packet failed: %w", err)
			}
		} else {
			// 处理未修改的原始数据包：直接写入原始字节（保留原始校验和）
			if err := writer.WritePacket(pd.captureInfo, pd.originalData); err != nil {
				return fmt.Errorf("write original packet failed: %w", err)
			}
		}
	}

	return nil
}

// 读取PCAP、分析映射、修改数据包、写入输出
func processPCAP(inputPath, outputPath string) error {
	// 1. 读取原始PCAP（获取解析后的数据包和原始字节数据）
	fmt.Printf("\nProcessing %s:\n", filepath.Base(inputPath))
	packets, packetDatas, linkType, err := readPCAP(inputPath)
	if err != nil {
		return fmt.Errorf("read pcap error: %w", err)
	}
	if len(packets) == 0 {
		fmt.Println("  Warning: Input PCAP is empty")
		return nil
	}

	// 2. 分析IPv4/IPv6映射表
	ipv4Map, ipv6Map := analyzeIPMappings(packets)

	// 打印映射信息
	if ipv4Map != nil {
		fmt.Println("  IPv4 mapping:")
		for origIP, newIP := range ipv4Map {
			fmt.Printf("    %s -> %s\n", origIP, newIP.String())
		}
	}
	if ipv6Map != nil {
		fmt.Println("  IPv6 mapping:")
		for origIP, newIP := range ipv6Map {
			fmt.Printf("    %s -> %s\n", origIP, newIP.String())
		}
	}

	// 3. 修改所有需要处理的数据包
	ip4Count, ip6Count := 0, 0
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for pktIdx, pkt := range packets {
		var (
			newLayers   []gopacket.SerializableLayer
			ipModified  = false
			ipv4Layer   *layers.IPv4 // 显式存储IPv4层
			ipv6Layer   *layers.IPv6 // 显式存储IPv6层
			linkLayer   gopacket.SerializableLayer
			tcpLayers   []*layers.TCP                // 存储TCP层
			udpLayers   []*layers.UDP                // 存储UDP层
			otherLayers []gopacket.SerializableLayer // 其他层
		)

		// 第一步：提取原始包中的所有层（按类型分类）
		for _, layer := range pkt.Layers() {
			switch l := layer.(type) {
			case gopacket.LinkLayer: // 链路层（Ethernet等）
				if sl, ok := l.(gopacket.SerializableLayer); ok {
					linkLayer = sl
				}
			case *layers.IPv4: // IPv4层
				ipv4Layer = l
			case *layers.IPv6: // IPv6层
				ipv6Layer = l
			case *layers.TCP: // TCP层
				tcpLayers = append(tcpLayers, l)
			case *layers.UDP: // UDP层
				udpLayers = append(udpLayers, l)
			default: // 其他层（应用层等）
				if sl, ok := l.(gopacket.SerializableLayer); ok {
					otherLayers = append(otherLayers, sl)
				}
			}
		}

		// 第二步：添加链路层（保持不变）
		if linkLayer != nil {
			newLayers = append(newLayers, linkLayer)
		}

		// 第三步：处理IPv4层（修改IP）
		if ipv4Layer != nil && ipv4Map != nil {
			origIP4 := ipv4Layer
			newIP4 := &layers.IPv4{
				Version:    origIP4.Version,
				IHL:        origIP4.IHL,
				TOS:        origIP4.TOS,
				Length:     origIP4.Length,
				Id:         origIP4.Id,
				Flags:      origIP4.Flags,
				FragOffset: origIP4.FragOffset,
				TTL:        origIP4.TTL,
				Protocol:   origIP4.Protocol,
				Checksum:   0,
				SrcIP:      origIP4.SrcIP,
				DstIP:      origIP4.DstIP,
				Options:    origIP4.Options,
			}
			// 应用IP映射
			if newSrc, ok := ipv4Map[origIP4.SrcIP.String()]; ok {
				newIP4.SrcIP = newSrc
			}
			if newDst, ok := ipv4Map[origIP4.DstIP.String()]; ok {
				newIP4.DstIP = newDst
			}
			newLayers = append(newLayers, newIP4)
			ip4Count++
			ipModified = true
		}

		// 第四步：处理IPv6层（修改IP）
		if ipv6Layer != nil && ipv6Map != nil {
			origIP6 := ipv6Layer
			newIP6 := &layers.IPv6{
				Version:      origIP6.Version,
				TrafficClass: origIP6.TrafficClass,
				FlowLabel:    origIP6.FlowLabel,
				Length:       origIP6.Length,
				NextHeader:   origIP6.NextHeader,
				HopLimit:     origIP6.HopLimit,
				SrcIP:        origIP6.SrcIP,
				DstIP:        origIP6.DstIP,
			}
			// 应用IP映射
			if newSrc, ok := ipv6Map[origIP6.SrcIP.String()]; ok {
				newIP6.SrcIP = newSrc
			}
			if newDst, ok := ipv6Map[origIP6.DstIP.String()]; ok {
				newIP6.DstIP = newDst
			}
			newLayers = append(newLayers, newIP6)
			ip6Count++
			ipModified = true
		}

		// 第五步：处理TCP层（绑定网络层）
		for _, origTCP := range tcpLayers {
			newTCP := *origTCP
			newTCP.Checksum = 0

			// 显式绑定具体的网络层
			switch {
			case ipv4Layer != nil && ipv4Map != nil:
				newTCP.SetNetworkLayerForChecksum(newLayers[len(newLayers)-1].(*layers.IPv4))
			case ipv6Layer != nil && ipv6Map != nil:
				newTCP.SetNetworkLayerForChecksum(newLayers[len(newLayers)-1].(*layers.IPv6))
			default:
				return fmt.Errorf("packet %d: TCP layer has no valid network layer", pktIdx)
			}
			newLayers = append(newLayers, &newTCP)
		}

		// 第六步：处理UDP层（绑定网络层）
		for _, origUDP := range udpLayers {
			newUDP := *origUDP
			newUDP.Checksum = 0

			// 显式绑定具体的网络层
			switch {
			case ipv4Layer != nil && ipv4Map != nil:
				newUDP.SetNetworkLayerForChecksum(newLayers[len(newLayers)-1].(*layers.IPv4))
			case ipv6Layer != nil && ipv6Map != nil:
				newUDP.SetNetworkLayerForChecksum(newLayers[len(newLayers)-1].(*layers.IPv6))
			default:
				return fmt.Errorf("packet %d: UDP layer has no valid network layer", pktIdx)
			}
			newLayers = append(newLayers, &newUDP)
		}

		// 第七步：添加其他层
		newLayers = append(newLayers, otherLayers...)

		// 第八步：序列化修改后的数据包，更新packetData
		if ipModified {
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, serializeOpts, newLayers...); err != nil {
				return fmt.Errorf("packet %d: serialize modified packet failed: %w", pktIdx, err)
			}
			// 标记为修改，并存储修改后的字节数据
			packetDatas[pktIdx].modified = true
			packetDatas[pktIdx].modifiedData = buf.Bytes()
		}
	}

	// 4. 写入输出文件
	if ipv4Map == nil && ipv6Map == nil {
		fmt.Println("  No IPv4/IPv6 traffic found. Copying file without modification.")
	}
	if err := writePCAP(outputPath, packetDatas, linkType); err != nil {
		return fmt.Errorf("write modified pcap failed: %w", err)
	}

	// 打印统计信息
	totalModified := ip4Count + ip6Count
	fmt.Printf("Modified %d packets (IPv4: %d, IPv6: %d)\n", totalModified, ip4Count, ip6Count)
	fmt.Printf("Output saved to: %s\n", outputPath)
	return nil
}

// getOutputPath 处理输出路径逻辑
func getOutputPath(inputPath, userOutput string) string {
	if userOutput == "" {
		ext := filepath.Ext(inputPath)
		if ext == "" {
			ext = ".pcap"
		}
		name := filepath.Base(inputPath[:len(inputPath)-len(ext)])
		return fmt.Sprintf("%s_randomized%s", name, ext)
	}

	if info, err := os.Stat(userOutput); err == nil && info.IsDir() {
		ext := filepath.Ext(inputPath)
		if ext == "" {
			ext = ".pcap"
		}
		name := filepath.Base(inputPath[:len(inputPath)-len(ext)])
		return filepath.Join(userOutput, fmt.Sprintf("%s_randomized%s", name, ext))
	}

	return userOutput
}

func main() {
	// 解析命令行参数
	var outputPath string
	flag.StringVar(&outputPath, "o", "", "Output directory or file path (default: ./原文件名_randomized.pcap)")
	flag.Parse()
	inputPath := flag.Arg(0)

	// 校验输入参数
	if inputPath == "" {
		fmt.Println("Error: Input PCAP file is required")
		fmt.Println("Usage: pcap-random <input.pcap> [-o <output>]")
		os.Exit(1)
	}
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		fmt.Printf("Error: Input file %s does not exist\n", inputPath)
		os.Exit(1)
	}

	// 确定最终输出路径
	finalOutputPath := getOutputPath(inputPath, outputPath)

	// 执行核心处理
	if err := processPCAP(inputPath, finalOutputPath); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
