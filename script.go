package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	apiURL   = "https://api.agi7.ai/agi7/api/alert/alerts"
	token    = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZXZpY2VfaWQiOiIiLCJlbWFpbCI6InNvbmcrdGF5bG9yQGFnaTcuYWkiLCJleHAiOjE3NzA0Nzc5NTQsIm1xdHRfdXNlcm5hbWUiOiJ1c2VyXzk5NSIsIm9yZ19pZCI6MzU4LCJyb2xlIjoiY3VzdG9tZXIiLCJ1c2VyX2lkIjo5OTV9.5LPxGT6Tdz4aMk4EWAkpXe5SDHtNk3lbW75ls7ynJjU"
	pageSize = 10
	maxCount = 1000
	tmpDir   = "/Users/xni/work/alerts" // 临时存储目录

	// 新API配置
	eventAPIBase = "https://test-api-3.agi7.ai/agi7/api/event"
	nvrToken     = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzA3MjM0MzksImlkIjoibnZyXzUwMTYiLCJtcXR0X3VzZXJuYW1lIjoibnZyXzUwMTYiLCJ0eXBlIjoibnZyIn0._IBDm2se-vsQfKAaGXSrL40CFBa95gcqQPK11NimPec"
	macAddress   = "c4:79:05:75:b9:3c"
	cameraName   = "TestCamera"
)

type AlertResp struct {
	Data []Alert `json:"data"`
}

type Alert struct {
	ID           string   `json:"id"`
	EventTypes   []string `json:"eventTypes"`
	CreatedAt    string   `json:"createdAt"`
	Snapshot     *Media   `json:"snapshot"`
	Video        *Media   `json:"video"`
	TargetImages []Media  `json:"targetImages"`
}

type Media struct {
	URL string `json:"url"`
}

// DownloadedMedia 记录下载的媒体文件信息
type DownloadedMedia struct {
	AlertID  string
	Type     string // "snapshot", "target_0", etc.
	FilePath string
	URL      string
}

// AlertMediaGroup 按 AlertID 分组的媒体文件
type AlertMediaGroup struct {
	AlertID  string
	Snapshot *DownloadedMedia
	Target   *DownloadedMedia
}

// ========== Step 1: Create Event Request/Response ==========

type CreateEventRequest struct {
	Event CreateEventData `json:"event"`
}

type CreateEventData struct {
	Tasks []CreateEventTask `json:"tasks"`
	Meta  CreateEventMeta   `json:"meta"`
	Raw   CreateEventRaw    `json:"raw"`
}

type CreateEventTask struct {
	ID    string          `json:"id"`
	Media CreateTaskMedia `json:"media"`
}

type CreateTaskMedia struct {
	Ext  string                 `json:"ext"`
	Type string                 `json:"type"`
	Meta map[string]interface{} `json:"meta"`
}

type CreateEventMeta struct {
	Camera CameraMeta `json:"camera"`
	UUID   string     `json:"uuid"`
}

type CameraMeta struct {
	MacAddress  string `json:"macAddress"`
	RemoteIndex int    `json:"remoteIndex"`
}

type CreateEventRaw struct {
	Alarm  AlarmData  `json:"alarm"`
	Struct StructData `json:"struct"`
}

type AlarmData struct {
	AlarmLevel   int    `json:"AlarmLevel"`
	AlarmSrcID   int    `json:"AlarmSrcID"`
	AlarmSrcName string `json:"AlarmSrcName"`
	AlarmSrcType int    `json:"AlarmSrcType"`
	AlarmType    string `json:"AlarmType"`
	RelatedID    string `json:"RelatedID"`
	TimeStamp    int64  `json:"TimeStamp"`
}

type StructData struct {
	RelatedID     string        `json:"RelatedID"`
	SrcID         int           `json:"SrcID"`
	SrcName       string        `json:"SrcName"`
	StructureInfo StructureInfo `json:"StructureInfo"`
	TimeStamp     int64         `json:"TimeStamp"`
}

type StructureInfo struct {
	ImageInfoList []ImageInfo `json:"ImageInfoList"`
	ImageNum      int         `json:"ImageNum"`
	ObjInfo       ObjInfo     `json:"ObjInfo"`
}

type ImageInfo struct {
	CaptureTime   int64         `json:"CaptureTime"`
	Format        int           `json:"Format"`
	Height        int           `json:"Height"`
	Index         int           `json:"Index"`
	RealImageMeta RealImageMeta `json:"RealImageMeta"`
	Size          int           `json:"Size"`
	Type          int           `json:"Type"`
	Width         int           `json:"Width"`
}

type RealImageMeta struct {
	Format string `json:"format"`
	Height int    `json:"height"`
	Path   string `json:"path"`
	Size   int    `json:"size"`
	Width  int    `json:"width"`
}

type ObjInfo struct {
	FaceInfoList            interface{}  `json:"FaceInfoList"`
	FaceNum                 int          `json:"FaceNum"`
	FirePointsInfoList      interface{}  `json:"FirePointsInfoList"`
	FirePointsNum           int          `json:"FirePointsNum"`
	NonMotorVehicleInfoList interface{}  `json:"NonMotorVehicleInfoList"`
	NonMotorVehicleNum      int          `json:"NonMotorVehicleNum"`
	PersonInfoList          []PersonInfo `json:"PersonInfoList"`
	PersonNum               int          `json:"PersonNum"`
	VehicleInfoList         interface{}  `json:"VehicleInfoList"`
	VehicleNum              int          `json:"VehicleNum"`
}

type PersonInfo struct {
	AppearTime          string        `json:"AppearTime"`
	AttributeInfo       AttributeInfo `json:"AttributeInfo"`
	Confidence          int           `json:"Confidence"`
	DisAppearTime       string        `json:"DisAppearTime"`
	Feature             string        `json:"Feature"`
	FeatureVersion      string        `json:"FeatureVersion"`
	LargePicAttachIndex int           `json:"LargePicAttachIndex"`
	PersonID            int           `json:"PersonID"`
	Position            string        `json:"Position"`
	RuleInfo            RuleInfo      `json:"RuleInfo"`
	SmallPicAttachIndex int           `json:"SmallPicAttachIndex"`
}

type AttributeInfo struct {
	AgeRange        int `json:"AgeRange"`
	BagFlag         int `json:"BagFlag"`
	BodyToward      int `json:"BodyToward"`
	CoatColor       int `json:"CoatColor"`
	Gender          int `json:"Gender"`
	HairLength      int `json:"HairLength"`
	ShoesTubeLength int `json:"ShoesTubeLength"`
	SleevesLength   int `json:"SleevesLength"`
	TrousersColor   int `json:"TrousersColor"`
	TrousersLength  int `json:"TrousersLength"`
}

type RuleInfo struct {
	PointList   interface{} `json:"PointList"`
	PointNum    int         `json:"PointNum"`
	RuleType    int         `json:"RuleType"`
	TriggerType int         `json:"TriggerType"`
}

// Create Event Response
type CreateEventResponse struct {
	Event CreateEventRespData `json:"event"`
}

type CreateEventRespData struct {
	ID               string                `json:"id"`
	Tasks            []CreateEventRespTask `json:"tasks"`
	CreateExpiration int64                 `json:"createExpiration"`
}

type CreateEventRespTask struct {
	ID       string        `json:"id"`
	Media    RespTaskMedia `json:"media"`
	Disabled bool          `json:"disabled"`
}

type RespTaskMedia struct {
	Type         string                 `json:"type"`
	ID           string                 `json:"id"`
	PreSignedUrl *PreSignedUrlData      `json:"preSignedUrl"`
	Ext          string                 `json:"ext"`
	Meta         map[string]interface{} `json:"meta"`
	Location     string                 `json:"location"`
}

type PreSignedUrlData struct {
	URL    string            `json:"url"`
	Method string            `json:"method"`
	Data   map[string]string `json:"data"`
	Bucket string            `json:"bucket"`
	Key    string            `json:"key"`
}

// ========== Step 4: Update Event Request ==========

type UpdateEventRequest struct {
	Event UpdateEventData `json:"event"`
}

type UpdateEventData struct {
	Tasks []UpdateEventTask `json:"tasks"`
	ID    string            `json:"id"`
}

type UpdateEventTask struct {
	Media UpdateTaskMedia `json:"media"`
	ID    string          `json:"id"`
}

type UpdateTaskMedia struct {
	Meta map[string]interface{} `json:"meta"`
}

func main() {
	client := &http.Client{Timeout: 120 * time.Second}

	var (
		results   []Alert
		endedAtMs int64 = 1770393599999
	)

	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log.Fatalf("create tmp dir error: %v", err)
	}

	for len(results) < maxCount {
		alerts, lastTime, err := fetchPage(client, endedAtMs)
		if err != nil {
			log.Fatalf("fetch error: %v", err)
		}
		if len(alerts) == 0 {
			break
		}

		downloadedFiles, err := downloadBatchMedia(client, alerts)
		if err != nil {
			log.Printf("download media error: %v", err)
		}

		log.Printf("downloaded %d media files for %d alerts", len(downloadedFiles), len(alerts))

		// 按 AlertID 分组处理
		groups := groupMediaByAlert(downloadedFiles)
		for _, group := range groups {
			if err := processAlertGroup(client, group); err != nil {
				log.Printf("process alert %s error: %v", group.AlertID, err)
			}
		}

		// 清理媒体文件
		cleanupMediaFiles(downloadedFiles)

		results = append(results, alerts...)
		endedAtMs = lastTime - 1

		log.Printf("fetched=%d total=%d", len(alerts), len(results))
	}

	log.Printf("DONE, total alerts=%d", len(results))
}

// groupMediaByAlert 按 AlertID 分组媒体文件
func groupMediaByAlert(files []DownloadedMedia) []AlertMediaGroup {
	groupMap := make(map[string]*AlertMediaGroup)

	for i := range files {
		f := &files[i]
		if _, ok := groupMap[f.AlertID]; !ok {
			groupMap[f.AlertID] = &AlertMediaGroup{AlertID: f.AlertID}
		}
		if f.Type == "snapshot" {
			groupMap[f.AlertID].Snapshot = f
		} else if strings.HasPrefix(f.Type, "target_") {
			groupMap[f.AlertID].Target = f
		}
	}

	var groups []AlertMediaGroup
	for _, g := range groupMap {
		groups = append(groups, *g)
	}
	return groups
}

// processAlertGroup 处理单个 alert 的所有4个步骤
func processAlertGroup(client *http.Client, group AlertMediaGroup) error {
	log.Printf("=== Processing alert: %s ===", group.AlertID)

	// Step 1: Create Event
	createResp, err := step1CreateEvent(client)
	if err != nil {
		return fmt.Errorf("step1 create event failed: %w", err)
	}
	log.Printf("Step 1: Created event: %s", createResp.Event.ID)

	// 找到 image_0 和 image_1 的预签名信息
	var image0Task, image1Task *CreateEventRespTask
	for i := range createResp.Event.Tasks {
		task := &createResp.Event.Tasks[i]
		if task.ID == "image_0" {
			image0Task = task
		} else if task.ID == "image_1" {
			image1Task = task
		}
	}

	// Step 2: Upload snapshot to S3 (image_0)
	if group.Snapshot != nil && image0Task != nil && image0Task.Media.PreSignedUrl != nil {
		if err := step2UploadToS3(client, group.Snapshot.FilePath, image0Task.Media.PreSignedUrl); err != nil {
			return fmt.Errorf("step2 upload snapshot failed: %w", err)
		}
		log.Printf("Step 2: Uploaded snapshot to S3")
	}

	// Step 3: Upload target to S3 (image_1)
	if group.Target != nil && image1Task != nil && image1Task.Media.PreSignedUrl != nil {
		if err := step2UploadToS3(client, group.Target.FilePath, image1Task.Media.PreSignedUrl); err != nil {
			return fmt.Errorf("step3 upload target failed: %w", err)
		}
		log.Printf("Step 3: Uploaded target to S3")
	}

	// Step 4: Update Event
	snapshotInfo := getImageInfo(group.Snapshot)
	targetInfo := getImageInfo(group.Target)

	if err := step4UpdateEvent(client, createResp.Event.ID, snapshotInfo, targetInfo); err != nil {
		return fmt.Errorf("step4 update event failed: %w", err)
	}
	log.Printf("Step 4: Updated event: %s", createResp.Event.ID)

	return nil
}

// step1CreateEvent 创建事件
func step1CreateEvent(client *http.Client) (*CreateEventResponse, error) {
	now := time.Now().Unix()
	relatedID := generateRelatedID()

	reqBody := CreateEventRequest{
		Event: CreateEventData{
			Tasks: []CreateEventTask{
				{
					ID: "image_0",
					Media: CreateTaskMedia{
						Ext:  "jpeg",
						Type: "image",
						Meta: map[string]interface{}{"type": 1},
					},
				},
				{
					ID: "image_1",
					Media: CreateTaskMedia{
						Ext:  "jpeg",
						Type: "image",
						Meta: map[string]interface{}{"type": 2},
					},
				},
			},
			Meta: CreateEventMeta{
				Camera: CameraMeta{
					MacAddress:  macAddress,
					RemoteIndex: 1,
				},
				UUID: uuid.New().String(),
			},
			Raw: CreateEventRaw{
				Alarm: AlarmData{
					AlarmLevel:   0,
					AlarmSrcID:   3,
					AlarmSrcName: "",
					AlarmSrcType: 8,
					AlarmType:    "SmartMotionDetectOn",
					RelatedID:    relatedID,
					TimeStamp:    now,
				},
				Struct: StructData{
					RelatedID: relatedID,
					SrcID:     3,
					SrcName:   cameraName,
					StructureInfo: StructureInfo{
						ImageInfoList: []ImageInfo{
							{
								CaptureTime: now,
								Format:      0,
								Height:      0,
								Index:       1,
								RealImageMeta: RealImageMeta{
									Format: "jpeg",
									Height: 1520,
									Path:   fmt.Sprintf("/var/fs_disk/edgebox/image/8/3/%s_1.jpg", relatedID),
									Size:   404576,
									Width:  2688,
								},
								Size:  400312,
								Type:  1,
								Width: 0,
							},
							{
								CaptureTime: now,
								Format:      0,
								Height:      0,
								Index:       2,
								RealImageMeta: RealImageMeta{
									Format: "jpeg",
									Height: 448,
									Path:   fmt.Sprintf("/var/fs_disk/edgebox/image/8/3/%s_2.jpg", relatedID),
									Size:   20894,
									Width:  256,
								},
								Size:  48564,
								Type:  2,
								Width: 0,
							},
						},
						ImageNum: 2,
						ObjInfo: ObjInfo{
							FaceInfoList:            nil,
							FaceNum:                 0,
							FirePointsInfoList:      nil,
							FirePointsNum:           0,
							NonMotorVehicleInfoList: nil,
							NonMotorVehicleNum:      0,
							PersonInfoList: []PersonInfo{
								{
									AppearTime: "",
									AttributeInfo: AttributeInfo{
										AgeRange:        98,
										BagFlag:         98,
										BodyToward:      0,
										CoatColor:       rand.Intn(18),
										Gender:          98,
										HairLength:      0,
										ShoesTubeLength: 0,
										SleevesLength:   0,
										TrousersColor:   rand.Intn(18),
										TrousersLength:  0,
									},
									Confidence:          0,
									DisAppearTime:       "",
									Feature:             "",
									FeatureVersion:      "",
									LargePicAttachIndex: 1,
									PersonID:            1047,
									Position:            "2395,6450;3242,9196",
									RuleInfo: RuleInfo{
										PointList:   nil,
										PointNum:    0,
										RuleType:    5,
										TriggerType: 0,
									},
									SmallPicAttachIndex: 2,
								},
							},
							PersonNum:       1,
							VehicleInfoList: nil,
							VehicleNum:      0,
						},
					},
					TimeStamp: now,
				},
			},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", eventAPIBase+"/events", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", nvrToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create event failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var createResp CreateEventResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w, body=%s", err, string(body))
	}

	return &createResp, nil
}

// step2UploadToS3 上传文件到 S3
func step2UploadToS3(client *http.Client, filePath string, preSignedUrl *PreSignedUrlData) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file failed: %w", err)
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("read file failed: %w", err)
	}

	// 创建 multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// 添加 form fields
	formFields := []string{"acl", "content-type", "key", "policy", "tagging", "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-signature"}
	for _, field := range formFields {
		if val, ok := preSignedUrl.Data[field]; ok {
			if err := writer.WriteField(field, val); err != nil {
				return fmt.Errorf("write field %s failed: %w", field, err)
			}
		}
	}

	// 添加文件
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("create form file failed: %w", err)
	}
	if _, err := part.Write(fileContent); err != nil {
		return fmt.Errorf("write file content failed: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("close writer failed: %w", err)
	}

	req, err := http.NewRequest("POST", preSignedUrl.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload to s3 failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// ImageFileInfo 图片文件信息
type ImageFileInfo struct {
	Size   int64
	Width  int
	Height int
}

// getImageInfo 获取图片文件信息
func getImageInfo(media *DownloadedMedia) *ImageFileInfo {
	if media == nil {
		return &ImageFileInfo{Size: 0, Width: 0, Height: 0}
	}

	fileInfo, err := os.Stat(media.FilePath)
	if err != nil {
		return &ImageFileInfo{Size: 0, Width: 0, Height: 0}
	}

	// 这里简化处理，实际可以用 image 包读取宽高
	// 根据类型设置默认宽高
	width, height := 2688, 1520 // snapshot 默认值
	if strings.HasPrefix(media.Type, "target_") {
		width, height = 256, 448 // target 默认值
	}

	return &ImageFileInfo{
		Size:   fileInfo.Size(),
		Width:  width,
		Height: height,
	}
}

// step4UpdateEvent 更新事件
func step4UpdateEvent(client *http.Client, eventID string, snapshotInfo, targetInfo *ImageFileInfo) error {
	reqBody := UpdateEventRequest{
		Event: UpdateEventData{
			ID: eventID,
			Tasks: []UpdateEventTask{
				{
					ID: "image_0",
					Media: UpdateTaskMedia{
						Meta: map[string]interface{}{
							"index":  1,
							"size":   snapshotInfo.Size,
							"width":  snapshotInfo.Width,
							"height": snapshotInfo.Height,
							"type":   1,
						},
					},
				},
				{
					ID: "image_1",
					Media: UpdateTaskMedia{
						Meta: map[string]interface{}{
							"index":  2,
							"size":   targetInfo.Size,
							"width":  targetInfo.Width,
							"height": targetInfo.Height,
							"type":   2,
						},
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", eventAPIBase+"/events", bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", nvrToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update event failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	return nil
}

// generateRelatedID 生成随机的 RelatedID
func generateRelatedID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 15)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// containsPerson 检查 eventTypes 数组是否包含 "person"
func containsPerson(eventTypes []string) bool {
	for _, t := range eventTypes {
		if t == "person" {
			return true
		}
	}
	return false
}

// cleanupMediaFiles 清理媒体文件
func cleanupMediaFiles(files []DownloadedMedia) {
	for _, f := range files {
		if err := os.Remove(f.FilePath); err != nil {
			log.Printf("remove file error: %s, %v", f.FilePath, err)
		}
	}
	log.Printf("cleaned up %d media files", len(files))
}

func fetchPage(client *http.Client, endedAt int64) ([]Alert, int64, error) {
	params := url.Values{}
	params.Set("withLocation", "true")
	params.Set("withLicense", "true")
	params.Set("eventTypes", "person")
	params.Set("siteIds", "")
	params.Set("cameraIds", "")
	params.Set("statuses", "")
	params.Set("personCoatColors", "")
	params.Set("personTrousersColors", "")
	params.Set("vehicleColors", "")
	params.Set("nonMotorVehiclePersonCoatColors", "")
	params.Set("vehiclePlateNos", "")
	params.Set("searchFlag", "0")
	params.Set("isCritical", "false")
	params.Set("hasVirtualGuard", "false")
	params.Set("hasSentry", "false")
	params.Set("paging.limit", strconv.Itoa(pageSize))
	params.Set("snapshotReq.width", "200")

	req, err := http.NewRequest("GET", apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("status=%d body=%s", resp.StatusCode, body)
	}

	var ar AlertResp
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, 0, err
	}

	// 找本页最后一条的 createdAt
	last := ar.Data[len(ar.Data)-1]
	lastTime, _ := strconv.ParseInt(last.CreatedAt, 10, 64)

	return ar.Data, lastTime, nil
}

// downloadBatchMedia 下载一批 alerts 的所有媒体文件
func downloadBatchMedia(client *http.Client, alerts []Alert) ([]DownloadedMedia, error) {
	var downloaded []DownloadedMedia

	for _, alert := range alerts {
		log.Printf("Alert ID=%s EventTypes=%v", alert.ID, alert.EventTypes)

		// 只处理 eventTypes 包含 person 的 alert
		if !containsPerson(alert.EventTypes) {
			continue
		}

		// 下载 snapshot
		if alert.Snapshot != nil && alert.Snapshot.URL != "" {
			filePath, err := downloadFile(client, alert.Snapshot.URL, alert.ID, "snapshot")
			if err != nil {
				log.Printf("download snapshot error for alert %s: %v", alert.ID, err)
			} else {
				downloaded = append(downloaded, DownloadedMedia{
					AlertID:  alert.ID,
					Type:     "snapshot",
					FilePath: filePath,
					URL:      alert.Snapshot.URL,
				})
			}
		}

		// 下载 target images (只取第一个)
		if len(alert.TargetImages) > 0 && alert.TargetImages[0].URL != "" {
			filePath, err := downloadFile(client, alert.TargetImages[0].URL, alert.ID, "target_0")
			if err != nil {
				log.Printf("download target image error for alert %s: %v", alert.ID, err)
			} else {
				downloaded = append(downloaded, DownloadedMedia{
					AlertID:  alert.ID,
					Type:     "target_0",
					FilePath: filePath,
					URL:      alert.TargetImages[0].URL,
				})
			}
		}
	}

	return downloaded, nil
}

// downloadFile 下载单个文件
func downloadFile(client *http.Client, fileURL, alertID, mediaType string) (string, error) {
	// 从 URL 获取文件扩展名
	ext := getFileExtension(fileURL)
	filename := fmt.Sprintf("%s_%s%s", alertID, mediaType, ext)
	filePath := filepath.Join(tmpDir, filename)

	// 创建文件
	out, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("create file error: %w", err)
	}
	defer out.Close()

	// 下载
	resp, err := client.Get(fileURL)
	if err != nil {
		os.Remove(filePath)
		return "", fmt.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		os.Remove(filePath)
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	// 写入文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(filePath)
		return "", fmt.Errorf("write file error: %w", err)
	}

	return filePath, nil
}

// getFileExtension 从 URL 获取文件扩展名
func getFileExtension(fileURL string) string {
	u, err := url.Parse(fileURL)
	if err != nil {
		return ".jpg"
	}
	path := u.Path
	ext := filepath.Ext(path)
	// 处理可能的查询参数
	if idx := strings.Index(ext, "?"); idx != -1 {
		ext = ext[:idx]
	}
	if ext == "" {
		return ".jpg"
	}
	return ext
}
