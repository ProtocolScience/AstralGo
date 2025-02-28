package client

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/ProtocolScience/AstralGo/client/internal/network"
	"github.com/ProtocolScience/AstralGo/client/internal/oicq"
	"github.com/ProtocolScience/AstralGo/message"
	"github.com/ProtocolScience/AstralGo/utils"
)

// ConnectionQualityInfo 客户端连接质量测试结果
// 延迟单位为 ms 如为 9999 则测试失败 测试方法为 TCP 连接测试
// 丢包测试方法为 ICMP. 总共发送 10 个包, 记录丢包数
type ConnectionQualityInfo struct {
	// ChatServerLatency 聊天服务器延迟
	ChatServerLatency int64
	// ChatServerPacketLoss 聊天服务器ICMP丢包数
	ChatServerPacketLoss int
	// LongMessageServerLatency 长消息服务器延迟. 涉及长消息以及合并转发消息下载
	LongMessageServerLatency int64
	// LongMessageServerResponseLatency 长消息服务器返回延迟
	LongMessageServerResponseLatency int64
	// SrvServerLatency Highway服务器延迟. 涉及媒体以及群文件上传
	SrvServerLatency int64
	// SrvServerPacketLoss Highway服务器ICMP丢包数.
	SrvServerPacketLoss int
}

func (c *QQClient) ConnectionQualityTest() *ConnectionQualityInfo {
	if !c.Online.Load() {
		return nil
	}
	r := &ConnectionQualityInfo{}
	wg := sync.WaitGroup{}
	wg.Add(2)

	currentServerAddr := c.servers[c.currServerIndex].String()
	go func() {
		defer wg.Done()
		var err error

		if r.ChatServerLatency, err = qualityTest(currentServerAddr); err != nil {
			c.error("test chat server latency error: %v", err)
			r.ChatServerLatency = 9999
		}

		if addr, err := net.ResolveIPAddr("ip", "ssl.htdata.qq.com"); err == nil {
			if r.LongMessageServerLatency, err = qualityTest((&net.TCPAddr{IP: addr.IP, Port: 443}).String()); err != nil {
				c.error("test long message server latency error: %v", err)
				r.LongMessageServerLatency = 9999
			}
		} else {
			c.error("resolve long message server error: %v", err)
			r.LongMessageServerLatency = 9999
		}
		if c.highwaySession.AddrLength() > 0 {
			if r.SrvServerLatency, err = qualityTest(c.highwaySession.SsoAddr[0].String()); err != nil {
				c.error("test srv server latency error: %v", err)
				r.SrvServerLatency = 9999
			}
		}
	}()
	go func() {
		defer wg.Done()
		res := utils.RunTCPPingLoop(currentServerAddr, 10)
		r.ChatServerPacketLoss = res.PacketsLoss
		if c.highwaySession.AddrLength() > 0 {
			res = utils.RunTCPPingLoop(c.highwaySession.SsoAddr[0].String(), 10)
			r.SrvServerPacketLoss = res.PacketsLoss
		}
	}()
	start := time.Now()
	if _, err := utils.HttpGetBytes("https://ssl.htdata.qq.com", ""); err == nil {
		r.LongMessageServerResponseLatency = time.Since(start).Milliseconds()
	} else {
		c.error("test long message server response latency error: %v", err)
		r.LongMessageServerResponseLatency = 9999
	}
	wg.Wait()
	return r
}

func (c *QQClient) initServers() {
	if c.Device() == nil {
		// must have device. Use c.UseDevice to set it!
		panic("client device is nil")
	}

	sso, err := getSSOAddress(c.Device())
	if err == nil && len(sso) > 0 {
		c.servers = append(sso, c.servers...)
	}

	// Create a context with a 5-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Perform the DNS lookup with the context
	adds, err := net.DefaultResolver.LookupIP(ctx, "ip", "msfwifi.3g.qq.com")

	if err == nil && len(adds) > 0 {
		var hostAddrs []netip.AddrPort
		for _, addr := range adds {
			ip, ok := netip.AddrFromSlice(addr.To4())
			if ok {
				hostAddrs = append(hostAddrs, netip.AddrPortFrom(ip, 8080))
			}
		}
		c.servers = append(hostAddrs, c.servers...)
	}
	if len(c.servers) == 0 {
		c.servers = []netip.AddrPort{ // default servers
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{43, 135, 106, 161}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{43, 154, 240, 13}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{111, 30, 187, 201}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{42, 81, 184, 206}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{119, 147, 190, 138}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{111, 206, 149, 85}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{39, 156, 126, 229}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{49, 7, 253, 65}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{49, 7, 253, 214}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{220, 194, 118, 236}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{125, 39, 196, 158}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{183, 47, 103, 84}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{222, 94, 109, 78}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 213, 142}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{42, 81, 184, 82}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{220, 194, 118, 230}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{120, 232, 130, 46}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{42, 81, 193, 250}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{120, 232, 31, 250}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{49, 7, 253, 177}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{111, 206, 149, 168}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{60, 29, 238, 126}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{120, 232, 31, 164}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{120, 241, 130, 195}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{180, 101, 246, 123}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 205, 252}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 163, 25}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{116, 147, 17, 39}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{121, 229, 94, 199}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{39, 156, 144, 113}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{111, 30, 182, 254}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{39, 156, 126, 178}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{120, 232, 31, 177}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{183, 47, 102, 213}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{153, 3, 46, 25}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{112, 86, 231, 155}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{60, 29, 242, 161}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{182, 50, 15, 44}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 148, 57, 39}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{221, 238, 41, 89}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 148, 54, 141}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{153, 3, 46, 82}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 148, 54, 16}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{153, 3, 46, 86}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 163, 66}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{14, 22, 9, 53}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 255, 5, 104}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{111, 30, 187, 227}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{117, 62, 243, 221}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{111, 30, 187, 245}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 148, 54, 20}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 187, 71}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{120, 241, 130, 216}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{117, 62, 242, 155}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 245, 16}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{42, 81, 179, 212}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 148, 54, 28}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{49, 7, 253, 58}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{121, 229, 94, 224}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{157, 148, 55, 96}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{36, 155, 207, 230}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{183, 2, 144, 33}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{180, 109, 192, 57}), 8080),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{123, 125, 0, 210}), 8080),
		}
	}
	pings := make([]int64, len(c.servers))
	wg := sync.WaitGroup{}
	wg.Add(len(c.servers))
	for i := range c.servers {
		go func(index int) {
			defer wg.Done()
			p, err := qualityTest(c.servers[index].String())
			if err != nil {
				pings[index] = 9999
				return
			}
			pings[index] = p
		}(i)
	}
	wg.Wait()
	sort.Slice(c.servers, func(i, j int) bool {
		return pings[i] < pings[j]
	})
	if len(c.servers) > 3 {
		c.servers = c.servers[0 : len(c.servers)/2] // 保留ping值中位数以上的server
	}
}

// connect 连接到 QQClient.servers 中的服务器
func (c *QQClient) connect() error {
	// init qq servers
	c.initServerOnce.Do(c.initServers)

	addr := c.servers[c.currServerIndex].String()
	c.info("connect to server: %v", addr)
	err := c.TCP.Connect(addr)
	c.currServerIndex++
	if c.currServerIndex == len(c.servers) {
		c.currServerIndex = 0
	}
	if err != nil {
		c.retryTimes++
		if c.retryTimes > len(c.servers) {
			return errors.New("All servers are unreachable")
		}
		c.error("connect server error: %v", err)
		return err
	}
	c.once.Do(func() {
		c.GroupMessageEvent.Subscribe(func(_ *QQClient, _ *message.GroupMessage) {
			c.stat.MessageReceived.Add(1)
			c.stat.LastMessageTime.Store(time.Now().Unix())
		})
		c.PrivateMessageEvent.Subscribe(func(_ *QQClient, _ *message.PrivateMessage) {
			c.stat.MessageReceived.Add(1)
			c.stat.LastMessageTime.Store(time.Now().Unix())
		})
		c.TempMessageEvent.Subscribe(func(_ *QQClient, _ *TempMessageEvent) {
			c.stat.MessageReceived.Add(1)
			c.stat.LastMessageTime.Store(time.Now().Unix())
		})
		c.onGroupMessageReceipt("internal", func(_ *QQClient, _ *groupMessageReceiptEvent) {
			c.stat.MessageSent.Add(1)
		})
		go c.netLoop()
	})
	c.retryTimes = 0
	c.ConnectTime = time.Now()
	return nil
}

// quickReconnect 快速重连
func (c *QQClient) quickReconnect() {
	c.Disconnect()
	time.Sleep(time.Millisecond * 200)
	if err := c.connect(); err != nil {
		c.error("connect server error: %v", err)
		c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "quick reconnect failed", Reconnection: true})
		return
	}
	if err := c.registerClient(); err != nil {
		c.error("register client failed: %v", err)
		c.Disconnect()
		c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "register error", Reconnection: true})
		return
	}
}

// Disconnect 中断连接, 不释放资源
func (c *QQClient) Disconnect() {
	_ = c.unRegisterClient()
	if c.firstLoginSucceed {
		c.TCP.Close()
		c.Online.Store(false)
	}
}

// sendAndWait 向服务器发送一个数据包, 并等待返回
func (c *QQClient) sendAndWait(seq uint16, pkt []byte, params ...network.RequestParams) (any, error) {
	type T struct {
		Response any
		Error    error
	}
	ch := make(chan T, 1)
	var p network.RequestParams

	if len(params) != 0 {
		p = params[0]
	}
	c.handlers.Store(seq, &handlerInfo{fun: func(i any, err error) {
		ch <- T{
			Response: i,
			Error:    err,
		}
	}, params: p, dynamic: false})

	err := c.sendPacket(pkt)
	if err != nil {
		c.handlers.Delete(seq)
		return nil, err
	}

	timeout := 15
	if v, ok := p["timeout"]; ok {
		timeout = v.(int)
	}

	retry := 0
	for {
		select {
		case rsp := <-ch:
			if timeout <= 0 {
				print("Done!\n")
			}
			return rsp.Response, rsp.Error
		case <-time.After(time.Second):
			if timeout <= 0 {
				print(".")
			} else {
				retry++
				if retry > timeout {
					c.handlers.Delete(seq)
					return nil, errors.New("Packet timed out in sendAndWait")
				}
			}
		}
	}

}

// sendPacket 向服务器发送一个数据包
func (c *QQClient) sendPacket(pkt []byte) error {
	err := c.TCP.Write(pkt)
	if err != nil {
		c.stat.PacketLost.Add(1)
	} else {
		c.stat.PacketSent.Add(1)
	}
	return errors.Wrap(err, "Packet failed to sendPacket")
}

// waitPacket
// 等待一个或多个数据包解析, 优先级低于 sendAndWait
// 返回终止解析函数
func (c *QQClient) waitPacket(cmd string, f func(any, error)) func() {
	c.waiters.Store(cmd, f)
	return func() {
		c.waiters.Delete(cmd)
	}
}

// waitPacketTimeoutSyncF
// 等待一个数据包解析, 优先级低于 sendAndWait
func (c *QQClient) waitPacketTimeoutSyncF(cmd string, timeout time.Duration, filter func(any) bool) (r any, e error) {
	notifyChan := make(chan bool, 4)
	defer c.waitPacket(cmd, func(i any, err error) {
		if filter(i) {
			r = i
			e = err
			notifyChan <- true
		}
	})()
	select {
	case <-notifyChan:
		return
	case <-time.After(timeout):
		return nil, errors.New("timeout")
	}
}

// sendAndWaitDynamic
// 发送数据包并返回需要解析的 response
func (c *QQClient) sendAndWaitDynamic(seq uint16, pkt []byte) ([]byte, error) {
	ch := make(chan []byte, 1)
	c.handlers.Store(seq, &handlerInfo{fun: func(i any, err error) { ch <- i.([]byte) }, dynamic: true})
	err := c.sendPacket(pkt)
	if err != nil {
		c.handlers.Delete(seq)
		return nil, err
	}
	select {
	case rsp := <-ch:
		return rsp, nil
	case <-time.After(time.Second * 15):
		c.handlers.Delete(seq)
		return nil, errors.New("Packet timed out in sendAndWaitDynamic")
	}
}

// SendSsoPacket
// 发送签名回调包给服务器并获取返回结果供提交
func (c *QQClient) SendSsoPacket(cmd string, body []byte) ([]byte, error) {
	seq, data := c.uniPacket(cmd, body)
	return c.sendAndWaitDynamic(seq, data)
}

// plannedDisconnect 计划中断线事件
func (c *QQClient) plannedDisconnect(_ *network.TCPClient) {
	c.debug("planned disconnect.")
	c.stat.DisconnectTimes.Add(1)
	c.Online.Store(false)
}

// unexpectedDisconnect 非预期断线事件
func (c *QQClient) unexpectedDisconnect(_ *network.TCPClient, e error) {
	c.error("unexpected disconnect: %v", e)
	c.stat.DisconnectTimes.Add(1)
	c.Online.Store(false)
	if err := c.connect(); err != nil {
		c.error("connect server error: %v", err)
		c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "connection dropped by server.", Reconnection: true})
		return
	}
	if err := c.registerClient(); err != nil {
		c.error("register client failed: %v", err)
		c.Disconnect()
		c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "register error", Reconnection: true})
		return
	}
}

// netLoop 通过循环来不停接收数据包
func (c *QQClient) netLoop() {
	errCount := 0
	for c.alive {
		l, err := c.TCP.ReadInt32()
		if err != nil {
			time.Sleep(time.Millisecond * 500)
			continue
		}
		if l < 4 || l > 1024*1024*10 { // max 10MB
			c.error("parse incoming packet error: invalid packet length %v", l)
			errCount++
			if errCount > 2 {
				go c.quickReconnect()
			}
			continue
		}
		data, _ := c.TCP.ReadBytes(int(l) - 4)
		resp, err := c.transport.ReadResponse(data)
		// pkt, err := packets.ParseIncomingPacket(data, c.sig.D2Key)
		if err != nil {

			info, ok := c.handlers.LoadAndDelete(uint16(resp.SequenceID))
			if ok {
				info.fun(&network.Packet{
					SequenceId:  uint16(resp.SequenceID),
					CommandName: resp.CommandName,
				}, err)
			}

			c.error("parse incoming packet error: %v", err)
			if errors.Is(err, network.ErrSessionExpired) || errors.Is(err, network.ErrPacketDropped) {
				c.Disconnect()
				go c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "session expired", Reconnection: true})
				continue
			} else if errors.Is(err, network.ErrChatBanned) {
				c.error("你号触发违规被限制了，所以不能说话，请上手机客户端查看情况。")
				c.Disconnect()
				go c.DisconnectedEvent.dispatch(c, &DisconnectedEvent{Message: "your chat permission has been stripped", Reconnection: false})
				continue
			}
			errCount++
			if errCount > 2 {
				go c.quickReconnect()
			}
			continue
		}
		if resp.EncryptType == network.EncryptTypeEmptyKey {
			m, e := c.oicq.Unmarshal(resp.Body)
			if errors.Is(e, oicq.ErrEmptyData) {
				continue //ignore empty data
			}
			if e != nil {
				c.error("decrypt payload error: %v, Data: %s, Cmd: %s", e, hex.EncodeToString(resp.Body), resp.CommandName)
				if errors.Is(e, oicq.ErrUnknownFlag) {
					go c.quickReconnect()
				}
				continue
			}
			resp.Body = m.Body
		}
		errCount = 0
		c.debug("rev pkt[%d] => Body: %v SSOReserveField: %s", resp.SequenceID, resp.CommandName, hex.EncodeToString(resp.SSOReserveField))
		c.stat.PacketReceived.Add(1)
		pkt := &network.Packet{
			SequenceId:  uint16(resp.SequenceID),
			CommandName: resp.CommandName,
			Payload:     resp.Body,
		}
		go func(pkt *network.Packet) {
			defer func() {
				if pan := recover(); pan != nil {
					c.error("panic on decoder %v : %v\n%s", pkt.CommandName, pan, debug.Stack())
					c.dump("packet decode error: %v - %v", pkt.Payload, pkt.CommandName, pan)
				}
			}()

			if decoder, ok := decoders[pkt.CommandName]; ok {
				// found predefined decoder
				info, ok := c.handlers.LoadAndDelete(pkt.SequenceId)
				var decoded any
				decoded = pkt.Payload
				if info == nil || !info.dynamic {
					pkt.Params = info.getParams()
					decoded, err = decoder(c, pkt)
					if err != nil {
						c.debug("decode pkt %v error: %+v", pkt.CommandName, err)
					}
				}
				if ok {
					info.fun(decoded, err)
				} else if f, ok := c.waiters.Load(pkt.CommandName); ok { // 在不存在handler的情况下触发wait
					f(decoded, err)
				}
			} else if f, ok := c.handlers.LoadAndDelete(pkt.SequenceId); ok {
				// does not need decoder
				f.fun(pkt.Payload, nil)
			} else {
				c.debug("Unhandled Command: %s\nSeq: %d\nThis message can be ignored.", pkt.CommandName, pkt.SequenceId)
			}
		}(pkt)
	}
}
