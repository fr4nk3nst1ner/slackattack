package banner

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const version = "1.0.2"

// RGB represents a color in RGB format
type RGB struct {
	R, G, B uint8
}

// Sprint returns a string with ANSI color codes
func (c RGB) Sprint(text string) string {
	return fmt.Sprintf("\033[38;2;%d;%d;%dm%s\033[0m", c.R, c.G, c.B, text)
}

// newRGB creates a new RGB color
func newRGB(r, g, b uint8) RGB {
	return RGB{R: r, G: g, B: b}
}

// Fade calculates a color gradient
func (start RGB) Fade(pos, total float32, point float32, end RGB) RGB {
	if total == 0 {
		return start
	}
	
	ratio := pos / total
	if ratio > 1 {
		ratio = 1
	}
	
	// Calculate midpoint color
	midR := float32(start.R) + (float32(end.R)-float32(start.R))*point/total
	midG := float32(start.G) + (float32(end.G)-float32(start.G))*point/total
	midB := float32(start.B) + (float32(end.B)-float32(start.B))*point/total
	
	// Calculate final color
	r := uint8(float32(start.R) + (midR-float32(start.R))*ratio)
	g := uint8(float32(start.G) + (midG-float32(start.G))*ratio)
	b := uint8(float32(start.B) + (midB-float32(start.B))*ratio)
	
	return RGB{r, g, b}
}

// colorizeText applies a random color gradient to text
func colorizeText(text string) string {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)

	startColor := newRGB(uint8(random.Intn(256)), uint8(random.Intn(256)), uint8(random.Intn(256)))
	firstPoint := newRGB(uint8(random.Intn(256)), uint8(random.Intn(256)), uint8(random.Intn(256)))

	strs := strings.Split(text, "")

	var coloredText string
	for i := 0; i < len(text); i++ {
		if i < len(strs) {
			coloredText += startColor.Fade(float32(i), float32(len(text)), float32(i%(len(text)/2)), firstPoint).Sprint(strs[i])
		}
	}

	return coloredText
}

// Print displays the banner with optional silence
func Print(silence bool) {
	if !silence {
		banner := getBanner()
		coloredBanner := colorizeText(banner)
		fmt.Println(coloredBanner)
	}
}

// getBanner returns the ASCII art banner
func getBanner() string {
	return fmt.Sprintf(`
  █████████  ████                    █████           █████████   █████   █████                     █████
 ███░░░░░███░░███                   ░░███           ███░░░░░███ ░░███   ░░███                     ░░███
░███    ░░░  ░███   ██████    ██████ ░███ █████    ░███    ░███ ███████ ███████   ██████    ██████ ░███ █████
░░█████████  ░███  ░░░░░███  ███░░███░███░░███     ░███████████░░░███░ ░░░███░   ░░░░░███  ███░░███░███░░███
 ░░░░░░░░███ ░███   ███████ ░███ ░░░ ░██████░      ░███░░░░░███  ░███    ░███     ███████ ░███ ░░░ ░██████░
 ███    ░███ ░███  ███░░███ ░███  ███░███░░███     ░███    ░███  ░███ ███░███ ██████░░███ ░███  ███░███░░███
░░█████████  █████░░████████░░██████ ████ █████    █████   █████ ░░█████ ░░█████░░████████░░██████ ████ █████
 ░░░░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░ ░░░░ ░░░░░    ░░░░░   ░░░░░   ░░░░░   ░░░░░  ░░░░░░░░  ░░░░░░ ░░░░ ░░░░░

Slackattack v%s
By: Jonathan Stines - @fr4nk3nst1ner
`, version)
} 