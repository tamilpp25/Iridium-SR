package main

import (
	"embed"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
)

var eventStream = make(chan string)

//go:embed frontend/public
var staticFolder embed.FS

func startServer() {
	r := gin.Default()
	r.GET("/api/start", apiStart)
	r.GET("/api/stop", apiStop)
	r.POST("/api/upload", apiUpload)
	r.GET("/api/stream", stream)
	r.Use(static.Serve("/", EmbedFolder(staticFolder, "frontend/public")))

	defer close(eventStream)
	err := r.Run(":1984")
	if err != nil {
		log.Fatalln("Could not start http server", err)
	}
}

func apiStart(c *gin.Context) {
	go openCapture()
}

func apiStop(c *gin.Context) {
	go closeHandle()
}

func apiUpload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		log.Println("Could not handle upload file", err)
		return
	}
	err = c.SaveUploadedFile(file, os.TempDir()+file.Filename)
	if err != nil {
		log.Println("Could not handle upload file", err)
		return
	}
	go openPcap(os.TempDir() + file.Filename)
}

func stream(c *gin.Context) {
	c.Stream(func(w io.Writer) bool {
		c.SSEvent("packetNotify", <-eventStream)
		return true
	})
}

func sendStreamMsg(msg string) {
	go func() {
		eventStream <- msg
	}()
}

type embedFileSystem struct {
	http.FileSystem
}

func (e embedFileSystem) Exists(prefix string, path string) bool {
	_, err := e.Open(path)
	if err != nil {
		return false
	}
	return true
}

func EmbedFolder(fsEmbed embed.FS, targetPath string) static.ServeFileSystem {
	fsys, err := fs.Sub(fsEmbed, targetPath)
	if err != nil {
		panic(err)
	}
	return embedFileSystem{
		FileSystem: http.FS(fsys),
	}
}
