package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VkCaptchaError represents a VK captcha error (error_code 14)
type VkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	CaptchaImg     string
	RedirectUri    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

// ParseVkCaptchaError parses a VK error response into VkCaptchaError
func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	code := int(codeFloat)

	redirectUri, _ := errData["redirect_uri"].(string)
	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}
	captchaImg, _ := errData["captcha_img"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	var sessionToken string
	if redirectUri != "" {
		if parsed, err := url.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:      code,
		ErrorMsg:       errorMsg,
		CaptchaSid:     captchaSid,
		CaptchaImg:     captchaImg,
		RedirectUri:    redirectUri,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

// IsCaptchaError checks if the error is a solvable Not Robot captcha
func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectUri != "" && e.SessionToken != ""
}

// solveVkCaptcha solves VK Not Robot captcha automatically and returns success_token
func solveVkCaptcha(captchaErr *VkCaptchaError) (string, error) {
	log.Printf("[Captcha] Solving Not Robot captcha automatically...")

	time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)

	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Step 1: Fetch the captcha HTML page to get powInput and cookies
	powInput, difficulty, cookies, err := fetchPowInput(captchaErr.RedirectUri)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}
	log.Printf("[Captcha] PoW input: %s, difficulty: %d", powInput, difficulty)

	// Step 2: Solve PoW
	hash := solvePoW(powInput, difficulty)
	log.Printf("[Captcha] PoW solved: hash=%s", hash)

	// Step 3: Call captchaNotRobot API
	successToken, err := callCaptchaNotRobot(sessionToken, hash, cookies)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("[Captcha] Success! Got success_token")
	return successToken, nil
}

// fetchPowInput fetches the captcha HTML page and extracts powInput, difficulty, and cookies
func fetchPowInput(redirectUri string) (string, int, string, error) {
	req, err := http.NewRequest("GET", redirectUri, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()

	// Capture cookies
	var cookieParts []string
	for _, setCookie := range resp.Header.Values("Set-Cookie") {
		parts := strings.Split(setCookie, ";")
		cookieParts = append(cookieParts, strings.TrimSpace(parts[0]))
	}
	cookieHeader := strings.Join(cookieParts, "; ")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, "", err
	}

	html := string(body)

	// Extract powInput
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return "", 0, "", fmt.Errorf("powInput not found in captcha HTML")
	}
	powInput := powInputMatch[1]

	// Extract difficulty
	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	diffMatch := diffRe.FindStringSubmatch(html)
	difficulty := 2
	if len(diffMatch) >= 2 {
		if d, err := strconv.Atoi(diffMatch[1]); err == nil {
			difficulty = d
		}
	}

	return powInput, difficulty, cookieHeader, nil
}

// solvePoW finds nonce where SHA-256(powInput + nonce) starts with '0' * difficulty
func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

// callCaptchaNotRobot executes all 4 steps of the captchaNotRobot API
func callCaptchaNotRobot(sessionToken, hash, cookies string) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		requestURL := "https://api.vk.ru/method/" + method + "?v=5.131"

		req, err := http.NewRequest("POST", requestURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("DNT", "1")
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}

		client := &http.Client{Timeout: 20 * time.Second}
		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	domain := "vk.com"
	baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=&access_token=",
		url.QueryEscape(sessionToken), url.QueryEscape(domain))

	// Step 1: settings
	log.Printf("[Captcha] Step 1/4: settings")
	_, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	time.Sleep(100*time.Millisecond + time.Duration(rand.Intn(100))*time.Millisecond)

	// Step 2: componentDone
	log.Printf("[Captcha] Step 2/4: componentDone")
	browserFp := fmt.Sprintf("%016x%016x", rand.Int63(), rand.Int63())
	deviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s",
		browserFp, url.QueryEscape(deviceJSON))

	_, err = vkReq("captchaNotRobot.componentDone", componentDoneData)
	if err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)

	// Step 3: check
	log.Printf("[Captcha] Step 3/4: check")
	cursorJSON := `[{"x":950,"y":500},{"x":945,"y":510},{"x":940,"y":520},{"x":938,"y":525},{"x":938,"y":525}]`
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfo := "d44f534ce8deb56ba20be52e05c433309b49ee4d2a70602deeb17a1954257785"

	baseDownlink := 8.0 + rand.Float64()*4.0
	downlinkStr := fmt.Sprintf("%.1f", baseDownlink)
	connectionDownlink := "[" + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
			"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		url.QueryEscape(cursorJSON),
		url.QueryEscape("[]"),
		url.QueryEscape("[]"),
		url.QueryEscape(connectionDownlink),
		browserFp,
		hash,
		answer,
		debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}

	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check response status: %s, full response: %v", status, checkResp)
	}

	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found in check response: %v", checkResp)
	}

	// Step 4: endSession
	log.Printf("[Captcha] Step 4/4: endSession")
	_, err = vkReq("captchaNotRobot.endSession", baseParams)
	if err != nil {
		log.Printf("[Captcha] Warning: endSession failed: %v", err)
	}

	return successToken, nil
}
