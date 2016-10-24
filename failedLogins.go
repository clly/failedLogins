package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/clly/failedLogins/assets"
	"github.com/gemsi/grok"
	"github.com/jehiah/strftime"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	file       = kingpin.Arg("file", "Filename to get IP addresses from").String()
	ipMap      = make(map[string]int)
	reportPath = "/root/report/%s"
)

func main() {
	kingpin.Parse()
	absolutePath, err := filepath.Abs(*file)
	assets.RestoreAssets("/tmp", "patterns")
	parser := grok.NewWithConfig(&grok.Config{NamedCapturesOnly: true})
	parser.AddPatternsFromPath("/tmp/patterns")
	if err != nil {
		fmt.Println(err)
	}
	if err != nil {
		fmt.Println(err)
	}
	fd, err := os.Open(absolutePath)
	if err != nil {
		fmt.Println(err)
	}
	defer fd.Close()
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		values, err := parser.Parse("%{IP_FROM_SECURE}", line)
		if err != nil {
			fmt.Println(err)
		}
		ip := values["ip"]
		if ip != "" {
			ipMap[ip]++
		}
	}
	dateFormat := strftime.Format("%Y%m%d", time.Now())
	dateReportPath := fmt.Sprintf(reportPath, dateFormat)
	fmt.Println(dateReportPath)
	wfd, err := os.OpenFile(dateReportPath, os.O_RDWR, 0666)
	if serr, ok := err.(*os.PathError); ok {
		wfd, err = os.Create(dateReportPath)
		fmt.Println(serr, "Creating Path")
	}
	defer wfd.Close()
	buffWriter := bufio.NewWriter(wfd)
	for k, v := range ipMap {
		if v > 30 {
			line := fmt.Sprintf("/usr/bin/sudo firewall-cmd --permanent --add-rich-rule 'rule family=\"ipv4\" source address=\"%s\" service name=\"ssh\" log limit value=\"30/m\" audit reject' # Requested %v times\n", k, v)
			err := blockIP(line)
			if err != nil {
				errLine := fmt.Sprintf("Failed to block ip %s requested %v times", k, v)
				buffWriter.WriteString(errLine)
			}
			fmt.Print(line)
			buffWriter.WriteString(line)
		}
	}
	buffWriter.Flush()
}

func blockIP(cmd string) error {
	cmdSl := strings.SplitN(cmd, " ", 1)
	command := cmdSl[0]
	args := cmdSl[1]
	eCmd := exec.Command(command, args)
	err := eCmd.Run()
	return err
}

/*
func getReportPath() {
	now := time.Now()
	now.Format()
}
*/
