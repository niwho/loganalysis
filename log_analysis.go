package main

import (
    "fmt"
    "runtime"
    // "io/ioutil"
    "bufio"
    "io"
    "os"
    "sync"
    "regexp"
    "time"
    "sort"
)

const MAXWORKS int = 32
type Logst struct{
    cnt int
    wg sync.WaitGroup
}

type St struct{
    ip string
    num int
    users []string
    device_ids []string
}
type Sts []*St
//排序支持
func (sts Sts) Len() int {
    return len(sts)
}

func (sts Sts) Less(i, j int) bool {
    return sts[i].num > sts[j].num
}

func (sts Sts) Swap(i, j int) {
    sts[i], sts[j] = sts[j], sts[i]
}
func (log *Logst) read(filename string) <-chan string{
    out := make(chan string,32)
    f, err := os.Open(filename)
    if err != nil{
        panic(err)
    }

    rd := bufio.NewReader(f)
    go func(){
        for {
            //fmt.Println("read", log.cnt)
            line, err := rd.ReadString('\n') //以'\n'为结束符读入一行

            if err != nil || io.EOF == err {
                fmt.Println("err:", err)
                close(out)
                break
            }
            //fmt.Println(line)
            log.cnt += 1
            out <- line
        }
        defer f.Close()
    }()
    return out
}

func (log * Logst) partAnalysis(out <-chan string) <-chan map[string]*St{
    //for str := range out
    result := make(chan map[string]*St)
    ip_pat, _ := regexp.Compile(`(?:ip)(\s\d+\.\d+\.\d+\.\d+)`)
    //ip_pat, _ := regexp.Compile(``)
    device_pat, _ := regexp.Compile(`device_id=(\d+)`)
    user_pat, _ := regexp.Compile(`user\s+([\d\.]+)`)
    //fmt.Printf("%v\n",ip_pat.FindStringSubmatch(str))

    log.wg.Add(MAXWORKS)
    for i:=0;i<MAXWORKS;i++{
        go func (){
            part_rt := make(map[string]*St)
            for line := range out{
                //fmt.Println("line", curi)
                // 正则表达式
                if mt:=ip_pat.FindStringSubmatch(line);len(mt)>0{
                    _, ok := part_rt[mt[1]]
                    if ok{
                        part_rt[mt[1]].num += 1
                    }else{
                        part_rt[mt[1]] = &St{ip: mt[1], num: 1, users: make([]string, 10, 10), device_ids: make([]string, 10, 10)}
                    }

                    if submt:=user_pat.FindStringSubmatch(line);len(submt)>0{
                        part_rt[mt[1]].users = append(part_rt[mt[1]].users, submt[1])
                    }

                    if submt:=device_pat.FindStringSubmatch(line);len(submt)>0{
                        part_rt[mt[1]].device_ids = append(part_rt[mt[1]].device_ids, submt[1])
                    }

                }
            }
            result <- part_rt
            log.wg.Done()
        }()
    }
    go func(){
        log.wg.Wait()
        close(result)
        fmt.Println("close result")
    }()
    return result
}

func (log * Logst) mergeResult(result <-chan map[string]*St){
    result_out := make(map[string]*St)
    for mapst := range result{
        //merge
        for k, v := range mapst{
            _, ok := result_out[k]
            if !ok{
                result_out[k] = v
            }else{


                result_out[k].num += v.num
                result_out[k].device_ids = append(result_out[k].device_ids, v.device_ids...)
                result_out[k].users = append(result_out[k].users, v.users...)
            }
        }
    }
    rt_list := make(Sts, 0, len(result_out))
    // 打印统计结果
    fmt.Println("\noutput:\n")
    for _, v := range result_out{
        rt_list = append(rt_list, v)
    }
    sort.Sort(rt_list)
    for i, v := range rt_list{
        fmt.Println(i, *v)
    }

}
func main(){
    now := time.Now()
    fmt.Println(runtime.NumCPU())
    fmt.Println("MAXWORKS", MAXWORKS)
    runtime.GOMAXPROCS(runtime.NumCPU())
    plog := &Logst{cnt:0,}
    out := plog.read("strrr.log")
    result := plog.partAnalysis(out)
    plog.mergeResult(result)
    fmt.Println("elapsed time:", time.Since(now))
}
