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
		case ip.IsMulticast():         // 组播地址（ff00::/8）
			continue
		case ip.IsLoopback():          // 环回地址（::1/128）
			continue
		case ip.IsLinkLocalUnicast():  // 链路本地地址（fe80::/10）
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

// readPCAP 读取PCAP文件，返回所有数据包和链路层类型
func readPCAP(filePath string) ([]gopacket.Packet, layers.LinkType, error) {
	// 使用 pcapgo 读取PCAP（纯Go，无C依赖）
	f, err := os.Open(filePath)
	if err != nil {
		return nil, layers.LinkTypeEthernet, fmt.Errorf("open pcap file failed: %w", err)
	}
	defer f.Close()

	// 自动检测PCAP格式（支持pcap和pcapng）
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, layers.LinkTypeEthernet, fmt.Errorf("create pcap reader failed: %w", err)
	}

	// 获取链路层类型
	linkType := layers.LinkType(reader.LinkType())

	var packets []gopacket.Packet
	for {
		// 读取单个数据包
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break // 读取完毕或出错
		}

		// 解析数据包
		pkt := gopacket.NewPacket(
			data,
			linkType,
			gopacket.DecodeOptions{NoCopy: true},
		)
		pkt.Metadata().CaptureInfo = ci
		packets = append(packets, pkt)
	}

	return packets, linkType, nil
}

// writePCAP 将修改后的数据包写入PCAP文件（纯Go实现，无C依赖）
func writePCAP(filePath string, packets []gopacket.Packet, linkType layers.LinkType) error {
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
	// 修复：移除 uint32() 强制转换，直接传递 linkType（layers.LinkType 类型匹配）
	if err := writer.WriteFileHeader(65535, linkType); err != nil {
		return fmt.Errorf("write pcap header failed: %w", err)
	}

	// 序列化并写入所有数据包
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for _, pkt := range packets {
		buf := gopacket.NewSerializeBuffer()
		// 转换为可序列化层
		var serializableLayers []gopacket.SerializableLayer
		for _, layer := range pkt.Layers() {
			if sl, ok := layer.(gopacket.SerializableLayer); ok {
				serializableLayers = append(serializableLayers, sl)
			}
		}
		// 序列化数据包
		if err := gopacket.SerializeLayers(buf, serializeOpts, serializableLayers...); err != nil {
			return fmt.Errorf("serialize packet failed: %w", err)
		}
		// 写入数据包（保留抓包元信息）
		if err := writer.WritePacket(pkt.Metadata().CaptureInfo, buf.Bytes()); err != nil {
			return fmt.Errorf("write packet failed: %w", err)
		}
	}

	return nil
}

// processPCAP 核心处理逻辑：读取PCAP、分析映射、修改数据包、写入输出
func processPCAP(inputPath, outputPath string) error {
	// 1. 读取原始PCAP
	fmt.Printf("\nProcessing %s:\n", filepath.Base(inputPath))
	packets, linkType, err := readPCAP(inputPath)
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

	// 3. 修改所有数据包
	var modifiedPackets []gopacket.Packet
	ip4Count, ip6Count := 0, 0

	for _, pkt := range packets {
		var newLayers []gopacket.SerializableLayer
		ipModified := false

		// 保留原始链路层
		if linkLayer := pkt.LinkLayer(); linkLayer != nil {
			if sl, ok := linkLayer.(gopacket.SerializableLayer); ok {
				newLayers = append(newLayers, sl)
			}
		}

		// 处理IPv4数据包
		if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil && ipv4Map != nil {
			origIP4 := ip4Layer.(*layers.IPv4)
			// 复制IPv4层字段（Id 大小写正确）
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
				Checksum:   0, // 自动计算
				SrcIP:      origIP4.SrcIP,
				DstIP:      origIP4.DstIP,
				Options:    origIP4.Options,
			}
			// 应用IPv4映射
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

		// 处理IPv6数据包
		if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil && ipv6Map != nil {
			origIP6 := ip6Layer.(*layers.IPv6)
			// 复制IPv6层字段
			newIP6 := &layers.IPv6{
				Version:     origIP6.Version,
				TrafficClass: origIP6.TrafficClass,
				FlowLabel:   origIP6.FlowLabel,
				Length:      origIP6.Length,
				NextHeader:  origIP6.NextHeader,
				HopLimit:    origIP6.HopLimit,
				SrcIP:       origIP6.SrcIP,
				DstIP:       origIP6.DstIP,
			}
			// 应用IPv6映射
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

		// 添加后续层（传输层/应用层）
		for _, layer := range pkt.Layers() {
			layerType := layer.LayerType()
			if layerType == layers.LayerTypeIPv4 || layerType == layers.LayerTypeIPv6 {
				continue // 已处理IP层
			}
			// 重置TCP/UDP校验和
			switch l := layer.(type) {
			case *layers.TCP:
				newTCP := *l
				newTCP.Checksum = 0
				newLayers = append(newLayers, &newTCP)
			case *layers.UDP:
				newUDP := *l
				newUDP.Checksum = 0
				newLayers = append(newLayers, &newUDP)
			default:
				if sl, ok := layer.(gopacket.SerializableLayer); ok {
					newLayers = append(newLayers, sl)
				}
			}
		}

		// 构建新数据包
		if ipModified {
			buf := gopacket.NewSerializeBuffer()
			serializeOpts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			if err := gopacket.SerializeLayers(buf, serializeOpts, newLayers...); err != nil {
				return fmt.Errorf("serialize modified packet failed: %w", err)
			}
			// 创建新数据包（保留元信息）
			newPkt := gopacket.NewPacket(
				buf.Bytes(),
				linkType,
				gopacket.DecodeOptions{NoCopy: true},
			)
			newPkt.Metadata().CaptureInfo = pkt.Metadata().CaptureInfo
			modifiedPackets = append(modifiedPackets, newPkt)
		} else {
			modifiedPackets = append(modifiedPackets, pkt)
		}
	}

	// 4. 写入输出文件
	if ipv4Map == nil && ipv6Map == nil {
		fmt.Println("  No IPv4/IPv6 traffic found. Copying file without modification.")
	}
	if err := writePCAP(outputPath, modifiedPackets, linkType); err != nil {
		return fmt.Errorf("write modified pcap failed: %w", err)
	}

	// 打印统计信息
	fmt.Printf("Modified %d packets (IPv4: %d, IPv6: %d)\n", len(modifiedPackets), ip4Count, ip6Count)
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