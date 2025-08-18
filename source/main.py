import os
import time
import requests

from toml import load
from shodan import Shodan
from rich.console import Console
from bs4 import BeautifulSoup

open_db = 'DISCORD-WEBHOOK-HERE'

class valhalla:
    def parseFileNames(line: str) -> tuple[str, str, str] | None:
        parts = [part for part in line.split(' ') if part]
        if len(parts) < 3:
            return None
        fileNameWithDate, sizeOf = parts[0], parts[2]
        if ':' in sizeOf or '-' in sizeOf:
            return None
        
        # Split filename at '.sql' to separate the date
        datePart = ''  # Default to empty string if no date
        fileName = fileNameWithDate
        if '.sql' or '.sqlite' in fileNameWithDate:
            sql_index = fileNameWithDate.find('.sql') + 4  # Include '.sql' in the filename
            fileName = fileNameWithDate[:sql_index]  # e.g., cipstrai_wp429_07082023_1345.sql
            datePart = fileNameWithDate[sql_index:] if sql_index < len(fileNameWithDate) else ''  # e.g., 2023-08-07
        return (fileName, sizeOf, datePart)

    @staticmethod
    def scan():
        console = Console()
        try:
            config = load('config.toml')
            keyConfig = config['key']
            queryConfig = config['query']
        except FileNotFoundError:
            console.print("[red]Error: config.toml not found[/red]")
            return
        except KeyError as e:
            console.print(f"[red]Error: Missing key {e} in config.toml[/red]")
            return

        key = keyConfig['_key']
        query = queryConfig['_query']
        shodan = Shodan(key=key)
        results = shodan.search_cursor(query)

        outputDir = 'urls'
        os.makedirs(outputDir, exist_ok=True)

        with open('urls.txt', 'a') as output:
            console.print(f"([blue]*[/blue]) scanning...")
            for result in results:
                time.sleep(1)  # avoid shodan rate limits
                try:
                    # define ip port and host's domain
                    ip = result['ip_str']
                    port = result['port']
                    hostname = result['hostnames'][0] if result.get('hostnames') else f'unknown-{ip}'

                    if 'http' not in result or 'html' not in result['http']:
                        continue

                    dirPath = os.path.join(outputDir, hostname)
                    os.makedirs(dirPath, exist_ok=True)

                    htmlSite = result['http']['html']
                    try:
                        bs4Html = BeautifulSoup(htmlSite, 'lxml')
                    except Exception as e:
                        console.print(f"[red]Error parsing HTML for {hostname}: {e}[/red]")
                        continue

                    with open(os.path.join(dirPath, 'site.html'), 'w', errors='ignore') as htmlFile:
                        htmlFile.write(bs4Html.prettify())

                    with open(os.path.join(dirPath, 'info.txt'), 'a', errors='ignore') as infoFile:
                        infoFile.write(f'Host: {ip}:{port} Domain: {hostname}\n')
                        infoFile.write('\n')
                        siteText = bs4Html.get_text().split('\n')

                        for text in siteText:
                            if '.sql' in text:
                                clearText = text.strip()
                                result = valhalla.parseFileNames(clearText)
                                if result:
                                    fileName, fileSize, datePart = result
                                    data = {
                                        "content": "",
                                        "username": "valhalla"
                                    }
                                    data["embeds"] = [
                                        {
                                            "title": f"Hostname: {hostname}",
                                            "fields": [
                                                {
                                                    "name": "Host",
                                                    "value": f"{ip}:{port}",
                                                    "inline": True
                                                },
                                                {
                                                    "name":"File Name",
                                                    "value": f"{fileName}",
                                                    "inline": True
                                                }, 
                                            ],
                                            "footer": {
                                                "text": f"File Size: {fileSize}"
                                            },
                                            "description": f"```{ip}:{port}/{fileName}```",
                                            "color": "3553599"
                                        }
                                    ]
                                    console.print(f"([green]+[/green]) {fileName} :: ([green]{fileSize}[/green]) ([underline white]{hostname}:{ip}:{port}[/underline white]) Date: {datePart}")
                                    infoFile.write(f'{clearText}\n')
                                    output.write(f'{ip}/{fileName}\n')
                                    requests.post(open_db, json=data)
                except (KeyError, IndexError) as e:
                    console.print(f"[red]Error processing result for {result.get('ip_str', 'unknown')}: {e}[/red]")
                    continue
                except Exception as e:
                    console.print(f"[red]Unexpected error: {e}[/red]")
                    continue

def main():
    valhalla.scan()

if __name__ == "__main__":
    main()
