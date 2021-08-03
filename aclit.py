#this script reads an alert mail from gmail and if it's has related subject then scripts block related ip addresses. you have to configure aws-cli in your server.

import subprocess
import imaplib
import email
from email.header import decode_header
import re
import json
from nslookup import  Nslookup as ns


# because i need to control ip addresses that belongs ciceksepeti
domain=["ciceksepeti.com","api.ciceksepeti.com"]

dserver=ns(dns_servers=["8.8.8.8"])

username = "gmail mail address"
password = "application password"
imap = imaplib.IMAP4_SSL("imap.gmail.com")
imap.login(username, password)
imap.select("INBOX")
(retcode, messages) = imap.search(None, (r'X-GM-RAW "subject:Alert Notification"'),('UNSEEN'))

ipad=[]



for num in messages[0].split():
    retcode, messages = imap.fetch(num,'(RFC822)')
    msg=email.message_from_bytes(messages[0][1])
    subject, encoding = decode_header(msg["Subject"])[0]
    if isinstance(subject, bytes):
        pass
    else:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                try:
                    # get the email body
                    body = part.get_payload(decode=True).decode()
                except:
                    pass
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    # print text/plain emails and skip attachments
                    ips=[]
                    for ip in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",body):
                        ipad.append(ip.group(1))

if len(ipad)>0:
    ip=list(dict.fromkeys(ipad))
else:
    exit("not")


def csip(domain):
    csip = list()
    for i in domain:
        ip = dserver.dns_lookup(i).response_full[0]
        listip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip)
        csip.append(listip)
    return csip

def bip(csip):
    bip = list()
    for e in csip:
        for it in e:
            bip.append(it)
    return bip


def checkip(bip,ipad):
    banip=list()
    for a in ipad:
        if a not in bip:
            banip.append(a)
        else:
            pass
    return banip

def updateip(id,key,ip):
    asd='aws waf update-ip-set --ip-set-id '+id+' --change-token '+key+\
    ' --updates Action="INSERT",IPSetDescriptor=\'{Type="IPV4",Value=\"'+ip+"/32\"}' --profile waf"
    d=subprocess.Popen(asd,stdout=subprocess.PIPE,shell=True)
    (upd, err) = d.communicate()
    x=upd.decode()


def gettoken():
    aws=subprocess.Popen("aws waf get-change-token --profile waf",stdout=subprocess.PIPE, shell=True)
    (awsr1, err) = aws.communicate()
    du=json.dumps(awsr1.decode())
    ast=json.loads(du)
    tu=(re.findall(r'"ChangeToken":\s"(\S+?)\"',ast))
    keys=["key"]
    di=dict(zip(keys,tu))
    return di


def main():
    x=csip(domain)
    y=bip(x)
    t=checkip(y,ipad)
    for i in ip:
        tk = gettoken().get('key')
        #waf profile id blacklist profile id
        updateip("you have to put waf profile id",tk,i)


if __name__ == "__main__":
    main()
