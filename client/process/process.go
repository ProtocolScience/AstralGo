package process

import (
	"fmt"
	"strings"
)

type Bar struct {
	percent int64  // 百分比
	cur     int64  // 当前进度位置
	total   int64  // 总进度
	rate    string // 进度条
	graph   string // 显示符号
	length  int    // 进度条长度
}

func (bar *Bar) NewOption(start, total int64, length int) {
	bar.cur = start
	bar.total = total
	bar.length = length
	if bar.graph == "" {
		bar.graph = "█"
	}
	bar.rate = strings.Repeat(" ", bar.length) // 初始化进度条为指定长度的空格
	bar.updateProgress()
}

func (bar *Bar) getPercent() int64 {
	if bar.total == 0 {
		return 0
	}
	return int64(float64(bar.cur) / float64(bar.total) * 100)
}

func (bar *Bar) updateProgress() {
	bar.percent = bar.getPercent()
	fullLen := int(bar.percent / 2) // 每2%填充一个字符，因为最大100%，字符数为length
	bar.rate = strings.Repeat(bar.graph, fullLen) + strings.Repeat(" ", bar.length-fullLen)
}

func (bar *Bar) NewOptionWithGraph(start, total int64, graph string, length int) {
	bar.graph = graph
	bar.NewOption(start, total, length)
}

func (bar *Bar) Play(cur int64) {
	bar.cur = cur
	bar.updateProgress()
	fmt.Printf("\r[%-*s]%3d%%  %8d/%d", bar.length+2, bar.rate, bar.percent, bar.cur, bar.total)
}

func (bar *Bar) Finish() {
	fmt.Println()
}
