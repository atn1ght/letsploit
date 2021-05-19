# coding: utf-8
import os
import subprocess
import json
from colorama import init
from termcolor import colored
from datetime import datetime
import requests
import os
import codecs
import glob
import sys
import time
import warnings
from urllib.request import urlopen
from bs4 import BeautifulSoup
import dload

#MSRC-API-KEY
apiKey='025968b3cc304af5b0982c07ed480066'

#types: info,result,warning,error,default
def log(type,text):
    dateTimeObj = datetime.now()
    ts = dateTimeObj.strftime("[%H:%M:%S]")
    if type=="info":
        fr="blue"
        bg="black"
        pre="[-] "
    elif type=="result":
        fr="green"
        bg="black"
        pre="[+] "
    elif type=="warning":
        fr="yellow"
        bg="black"
        pre="[!] "
    elif type=="error":
        fr="red"
        bg="black"
        pre="[!!] "
    else:
        fr="white"
        bg="black"
        pre=""

    print(ts+(colored(pre+text,fr)))
    return

def getUpdate(id):
    #id 2020-May, 2020-Jun,...
    url = "https://api.msrc.microsoft.com/cvrf/"+id+"?api-version=2016"
    payload = {}
    files = {}
    headers = {
      'Api-Key': apiKey,
      'Accept': 'application/json'
    }
    response = requests.request("GET", url, headers=headers, data = payload, files = files)
    data = response.json()
    if "Vulnerability" in data:
        items = data['Vulnerability']
    else:
        items=[[]]
    return items

def getAllUpdates():
    url = "https://api.msrc.microsoft.com/updates/?api-version=2016"
    payload = {}
    headers = {
      'Accept': 'application/json',
      'Api-Key': apiKey
    }
    response = requests.request("GET", url, headers=headers, data = payload)
    data = response.json()
    items = data['value']
    return items

def getProducts(id):
    #id 2020-May, 2020-Jun,...
    url = "https://api.msrc.microsoft.com/cvrf/"+id+"?api-version=2016"
    payload = {}
    files = {}
    headers = {
      'Api-Key': apiKey,
      'Accept': 'application/json'
    }
    response = requests.request("GET", url, headers=headers, data = payload, files = files)
    data = response.json()
    items = data['ProductTree']
    return items

def updateMsrcData():
    updateInfos=getAllUpdates()
    for i in updateInfos:

        if os.path.exists(os.getcwd()+"/vulns/"+i["ID"]+".csv"):
            log("info",i["ID"]+":,Release Date,"+i["InitialReleaseDate"]+","+"Exists")
            continue
        else:
            log("result",i["ID"]+":,Release Date,"+i["InitialReleaseDate"]+","+"Downloading...")
        fo=open(os.getcwd()+"/vulns/"+i["ID"]+".csv","w")
        updates=getUpdate(i["ID"])
        target=[]

        for j in updates:
            if "Remediations" in j:
                for product in j["Remediations"]:
                    if "ProductID" in product:
                        if "Value" in j["Title"]:
                            if "Supercedence" in product:
                                ss=product["Supercedence"]
                            else:
                                ss="-1"
                            target.append(j["Title"]["Value"]+","+j["CVE"]+","+product["Description"]["Value"]+","+product["ProductID"][0]+","+ss)

        products=getProducts(i["ID"])
        productIDNameMapping=[]
        if "Items" in products["Branch"][0]:
            for k in products["Branch"][0]["Items"]:
                for m in k["Items"]:
                    productIDNameMapping.append(m)
        for a in target:
            a=a.split(",")
            for b in productIDNameMapping:
                if a[3]==b["ProductID"]:
                    fo.write(b["Value"]+","+a[2]+","+a[3]+","+a[1]+","+a[0]+"\n")
        fo.close()

def updatePublicPOCs():
    dload.git_clone("https://github.com/nomi-sec/PoC-in-GitHub.git")
    log("result","POCs updated!")

def logo():
    print("")
    print("< Letsploit 1.01 | atn1ght/Github | @atn1ght1/Twitter >")
    print("   \\")
    print("    \\")
    print("        .--.")
    print("       |o_o |")
    print("       |:_/ |")
    print("      //   \ \\")
    print("     (|     | )")
    print("    /'\_   _/`\\")
    print("    \___)=(___/")
    print("")
    return

def replace_all(text, dic):
    for i, j in dic.iteritems():
        text = text.replace(i, j)
    return text

def getVer():
    output = subprocess.check_output("ver", shell=True)
    ver=str(output).split(" ")[3].split("]")[0].split(".")[2:4]
    ver=ver[0]+"."+ver[1]
    return ver

def getBuild(ver):
    if "18363" in ver:
        build="1909"
    if "18362" in ver:
        build="1903"
    if "17763" in ver:
        build="1809"
    if "17134" in ver:
        build="1803"
    if "16299" in ver:
        build="1709"
    if "15063" in ver:
        build="1703"
    if "14393" in ver:
        build="1607"
    if "10586" in ver:
        build="1511"
    if "19041" in ver:
        build="2004"
    if "19042" in ver:
        build="20H2"
    return build

def showLatestandMissingPatches(osver):
    with open("builds.csv") as file_in:
        builds = []
        for line in file_in:
            builds.append(line)

    for build in builds:
        if ver==build.rstrip().split(",")[2] or ver==build.rstrip().split(",")[3]:
            last=build.rstrip().split(",")
            log("info","Installed: "+str(last)+"\n")
            break;

    missing= []
    for build in builds:
        if osver in str(build.rstrip().split(",")[0]) and last!=build.rstrip().split(",")[1]:
            log("info","Missing: "+str(build.rstrip().split(",")))
            missing.append(build.rstrip().split(" ")[0])
        if ver==build.rstrip().split(",")[2] or ver==build.rstrip().split(",")[3]:
            break;

    missing=sorted(set(missing), key=missing.index)
    if (last[0].split(" ")[0] in missing):
        missing=missing[:-1]

    missing_strs=[]
    for m in missing:
        m=m.replace("-12","-Dec")
        m=m.replace("-11","-Nov")
        m=m.replace("-10","-Oct")
        m=m.replace("-09","-Sep")
        m=m.replace("-08","-Aug")
        m=m.replace("-07","-Jul")
        m=m.replace("-06","-Jun")
        m=m.replace("-05","-May")
        m=m.replace("-04","-Apr")
        m=m.replace("-03","-Mar")
        m=m.replace("-02","-Feb")
        m=m.replace("-01","-Jan")
        missing_strs.append(m)

    return missing_strs

def checkPublicExploits(cve):
    allpocs=glob.glob("PoC-in-GitHub/*/*/*.json")
    i=0
    for val in allpocs:
        if cve+"." in val:
            with open(val, encoding="utf8") as json_file:
                x=json_file.read()
                data=json.loads(x)
                for exploits in data:
                    if exploits["description"] is None:
                        desc="null"
                    else:
                        desc=exploits["description"]
                    log("warning","("+str(exploits["stargazers_count"])+" Stars) "+exploits["html_url"]+" -> "+desc)
                    i=i+1
    return i

def kb2cve(missing,osver,onlyPublicExploits=True):
    exvuln=""
    excve=""
    for m in missing:
        with open(os.getcwd()+"/vulns/"+m+".csv", encoding='utf-8', errors='ignore') as csv_file:
            print("")
            log("info",m)
            for row in csv_file:
                if len(row)<1:
                    continue
                try:
                    product,kb,supkb,cve,details=row.split(",")
                except:
                    continue

                if product.startswith("Windows 10") or product.startswith("Windows 7"):
                    if not "ARM" in product:
                        if not "HoloLens" in product:
                            if "10 for 32" in product or "10 for x64" in product or "Version" in product:
                                if osver in product or "Windows 10 for x64" in product:
                                    if cve==excve:
                                        continue
                                    vuln="Vuln: "+product+" "+cve+" "+kb+" "+details.strip("\r\n")
                                    excve=cve
                                    if onlyPublicExploits:
                                        tmp=checkPublicExploits(cve)
                                        if tmp>0:
                                            log("result",vuln)
                                    else:
                                        log("result",vuln)
                                        checkPublicExploits(cve)
    return

def updateBuildsAlt():
    #w_20H2="https://support.microsoft.com/en-us/help/4581839"
    #ws_2012_r2="https://support.microsoft.com/en-us/help/4009470"
    #ws_2012="https://support.microsoft.com/en-us/help/4009471"
    #w7_2008_r2="https://support.microsoft.com/en-us/help/4009469"
    #w_2004="https://support.microsoft.com/en-us/help/4555932"
    #w_1909="https://support.microsoft.com/en-us/help/4581839"
    #w_1903="https://support.microsoft.com/en-us/help/4498140"
    #w_1809="https://support.microsoft.com/en-us/help/4464619"
    #w_1709="https://support.microsoft.com/en-us/help/4043454"
    #w_1703="https://support.microsoft.com/en-us/help/4018124"
    #w_1607="https://support.microsoft.com/en-us/help/4000825"
    #w_1511="https://support.microsoft.com/en-us/help/4000824"
    #w_1511="https://support.microsoft.com/en-us/help/4000824"

    u="https://support.microsoft.com/en-us/help/4581839"
    page = urlopen(u)
    soup = BeautifulSoup(page, "html.parser")
    a = soup.findAll("a", attrs={"class":"supLeftNavLink"})
    pp=[]
    with open("builds.csv", 'w') as out_file:
        for p in a:
            txt = p.text

            if "update history" in txt:
                current=txt[20:24]
                current=current+","
                if "vers" in current:
                    current="1503,"
                continue
            if not "Windows 10 Mobile" in txt:
                tmp=current+txt.replace(",","")
                tmp=tmp.replace(")","")
                tmp=tmp.replace(" Preview",",Preview")
                tmp=tmp.replace(" Out-of-band",",Out-of-band")
                tmp=tmp.replace(" (OS Build ",",")
                tmp=tmp.replace(" (OS Builds ",",")
                tmp=tmp.replace(" and ",",")
                tmp=tmp.replace(" "+b'\xe2\x80\x94'.decode('utf-8')+" ",",")
                tmp=tmp.replace(b'\xe2\x80\x94'.decode('utf-8'),",")
                tmp=tmp.replace(" (Monthly Rollup",",Monthly Rollup")
                tmp=tmp.replace(" (Preview of Monthly Rollup",",Preview of Monthly Rollup")
                tmp=tmp.replace(" (Security-only update",",Security-only update")
                tmp=tmp.replace(" (OS Build","")
                tmp=tmp.replace(" (Security only update",",Security only update")
                tmp=tmp.replace(" (Monthly rollup",",Monthly rollup")
                tmp=tmp.replace(",",";")
                tmp=tmp.replace(" ",".")
                tmp=tmp.replace("-",";")
                tmp=tmp.replace("Out;of;band","OoB")
                tmp=tmp.replace("Security;only","Security.only")
                out_file.write(str(tmp)+"\n")
    return

def showLatestandMissingPatches(osver,ver):
    missing=[]
    missing_rollups=[]
    with open("builds.csv") as file_in:
        builds = []
        for line in file_in:
            builds.append(line)

    for build in builds:
        if osver in build:
            if ver in build:
                log("result","Last installed: "+build.strip("\n"))
                lastmonth=build.split(";")[1].split(".")[0]
                break
            missing.append(build)

    for m in missing:
        year=m.split(";")[1].split(".")[2]
        m=m.split(";")[1].split(".")[0]
        m=m.replace("January","Jan")
        m=m.replace("February","Feb")
        m=m.replace("March","Mar")
        m=m.replace("April","Apr")
        m=m.replace("May","May")
        m=m.replace("June","Jun")
        m=m.replace("July","Jul")
        m=m.replace("August","Aug")
        m=m.replace("September","Sep")
        m=m.replace("October","Oct")
        m=m.replace("November","Nov")
        m=m.replace("December","Dec")
        missing_rollups.append(year+"-"+m)
        missing_rollups = list(dict.fromkeys(missing_rollups))

    return missing_rollups

def patchlevel(ver=False):
    if ver is False:
        output = subprocess.check_output("ver", shell=True)
        ver=str(output).split(" ")[3].split("]")[0].split(".")[2]
        ver=getVer()

    osver=getBuild(ver)

    log("info","OS Version: "+ver+" -> "+osver)
    missing=showLatestandMissingPatches(osver,ver)
    log("info","Missing Rollups: "+str(missing))
    return missing

def showBuilds():
    with open("builds.csv") as file_in:
        builds = []
        tmp=[]
        for line in file_in:
            tmp.append(str(line).strip("\n"))
        tmp.reverse()
        for logline in tmp:
            log("result",logline)

warnings.filterwarnings('ignore')
init()
logo()

output = subprocess.check_output("ver", shell=True)
ver=str(output).split(" ")[3].split("]")[0].split(".")[2]
ver=getVer()
osver=getBuild(ver)

if len(sys.argv) > 1:
    if (sys.argv[1]=="-builds"):
        showBuilds()
        quit()
    elif (sys.argv[1]=="-patchlevel"):
        if len(sys.argv) > 2:
            patchlevel(sys.argv[2])
        else:
            patchlevel()
        quit()
    elif (sys.argv[1]=="-vulns"):
        if len(sys.argv) > 2:
            missing=patchlevel(sys.argv[2])
            tmposver=getBuild(sys.argv[2])
            kb2cve(missing,tmposver,False)
        else:
            missing=patchlevel()
            kb2cve(missing,osver,False)
        quit()
    elif (sys.argv[1]=="-pocs"):
        if len(sys.argv) > 2:
            missing=patchlevel(sys.argv[2])
            tmposver=getBuild(sys.argv[2])
            kb2cve(missing,tmposver,True)
        else:
            missing=patchlevel()
            kb2cve(missing,osver,True)
        quit()
    elif (sys.argv[1]=="-updateCves"):
        updateMsrcData()
        quit()
    elif (sys.argv[1]=="-updatePocs"):
        updatePublicPOCs()
        quit()
    elif (sys.argv[1]=="-updateBuilds"):
        log("info","Update current W10 Build/Revision List...")
        updateBuildsAlt()
        log("result","Done!")
        quit()

print("Usage:")
print(sys.argv[0]+" -builds           :Output all available builds/revisions")
print(sys.argv[0]+" -patchlevel <rev> :Output patchlevel and missing patches only")
print(sys.argv[0]+" -vulns <rev>      :Output all unpatched CVEs")
print(sys.argv[0]+" -pocs <rev>       :Output all unpatched CVEs with public POCs on Github")
print("")
print("Use <rev> to query informations about another system. If nothing is specified the local system is evaluated.")
print("Example: <rev>=19041.572 > W10 2004 Patchlevel October 2020")
print("")
print(sys.argv[0]+" -updateCves       :Update KB/CVE Table via MSRC API")
print(sys.argv[0]+" -updatePocs       :Update POC Table via GIT")
print(sys.argv[0]+" -updateBuilds     :Update BUILDS via MS Update History Website")
print("")
print("Windows 10 Client OS 1503-20H2 supported.\n")
quit()
