#!/usr/bin/env python3

# 20201020 - Add a function to add a single prefix to a local prefixlist - Dan
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import cloudgenix_settings
import sys
import logging
import logging.handlers as handlers
import os
import datetime
from datetime import datetime, timedelta
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import csv
import schedule

# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Circuit Alerts'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

logger = logging.getLogger('event_log')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logHandler = handlers.RotatingFileHandler('download_log.txt', maxBytes=5000000, backupCount=2)
logHandler.setLevel(logging.INFO)
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import EMAIL_FROM
    from cloudgenix_settings import EMAIL_PASSWORD
    from cloudgenix_settings import EMAIL_TO

except ImportError:
    EMAIL_FROM = None
    EMAIL_PASSWORD = None
    EMAIL_PASSWORD = EMAIL_TO

global circuit_list
circuit_list = []


def run_reports(cgx):
    global circuit_list
    print("############ New Check ##############") 
    circuit_list_ignore = []
    
    for index in range(len(circuit_list)):
        circuit_list[index]["active"] = False
    
    mos_avg = 4.0
    
    site_id2n = {}
    for site in cgx.get.sites().cgx_content["items"]:
        site_id2n[site["id"]] = site["name"] 
    start = datetime.utcnow()
    start_time = start.isoformat()[:-3]+'Z'
    data = {"start_time":start_time,"interval":"1hour","filter":{"site":[],"path":[]},"metrics":[{"name":"LqmMosPointMetric","unit":"count"}]}
    resp = cgx.post.monitor_lqm_point_metrics(data)

    while resp.status_code == 429:
        time.sleep(1)
        resp = cgx.post.monitor_lqm_point_metrics(data)
    data_info = resp.cgx_content["metrics"][0]["sites"]
    for site in data_info:
        try:
            site_name = site_id2n[site["site_id"]]
        except:
            site_name = site["site_id"]
        for path in site["paths"]:
            downlink_mos_avg = float(path["data"]["downlink_mos_avg"])
            if downlink_mos_avg < mos_avg:
                circuit_data = {}
                circuit_data["site_name"] = site_name
                circuit_data["path_id"] = path["path_id"]
                circuit_data["direction"] = "Ingress"
                circuit_data["MOS"] = downlink_mos_avg
                data = {"type":"basenet","links":[path["path_id"]],"links_only":False}
                for results in cgx.post.topology(data).cgx_content["links"]:
                    if results["path_id"] == path["path_id"]:
                        if results["type"] == "vpn":
                            try:
                                if "DC" in results["source_site_name"]:
                                    circuit_data["target_site_name"] = results["source_site_name"]
                                    circuit_data["target_wan_network"] = results["source_wan_network"]
                                    circuit_data["source_site_name"] = results["target_site_name"]
                                    circuit_data["source_wan_network"] = results["target_wan_network"]
                                else:
                                    circuit_data["source_site_name"] = results["source_site_name"]
                                    circuit_data["source_wan_network"] = results["source_wan_network"]
                                    circuit_data["target_site_name"] = results["target_site_name"]
                                    circuit_data["target_wan_network"] = results["target_wan_network"]
                                if results["in_use"]:
                                    ignore=False
                                    tags = cgx.get.sites(site_id=site["site_id"]).cgx_content["tags"]
                                    if tags:
                                        for item in tags:
                                            if item == "alert_ignore":
                                                ignore=True
                                    if not ignore:
                                        circuit_data["alert"] = True
                                        circuit_data["active"] = True
                                        circuit_data["active_count"] = 1
                                        
                                        active_found = False
                                        for index in range(len(circuit_list)):
                                            if circuit_data["path_id"] == circuit_list[index]["path_id"] and circuit_data["direction"] == circuit_list[index]["direction"]:
                                                circuit_list[index]["active"] = True
                                                circuit_list[index]["active_count"] += 1
                                                active_found = True
                                        if not active_found:
                                            circuit_list.append(circuit_data)
                                    else:
                                        print("Ignoring alerts for site " + site_name)
                                        logger.info("Ignoring alerts for site " + site_name)
                                        circuit_list_ignore.append(path["path_id"])
                            except:
                                print("Failed")                                                   
                                                    
            uplink_mos_avg = float(path["data"]["uplink_mos_avg"])
            if uplink_mos_avg < mos_avg:
                circuit_data = {}
                circuit_data["site_name"] = site_name
                circuit_data["path_id"] = path["path_id"]
                circuit_data["direction"] = "Egress"
                circuit_data["MOS"] = uplink_mos_avg
                data = {"type":"basenet","links":[path["path_id"]],"links_only":False}
                for results in cgx.post.topology(data).cgx_content["links"]:
                    if results["path_id"] == path["path_id"]:
                        if results["type"] == "vpn":
                            try:
                                if "DC" in results["source_site_name"]:
                                    circuit_data["target_site_name"] = results["source_site_name"]
                                    circuit_data["target_wan_network"] = results["source_wan_network"]
                                    circuit_data["source_site_name"] = results["target_site_name"]
                                    circuit_data["source_wan_network"] = results["target_wan_network"]
                                else:
                                    circuit_data["source_site_name"] = results["source_site_name"]
                                    circuit_data["source_wan_network"] = results["source_wan_network"]
                                    circuit_data["target_site_name"] = results["target_site_name"]
                                    circuit_data["target_wan_network"] = results["target_wan_network"]
                                if results["in_use"]:
                                    ignore=False
                                    tags = cgx.get.sites(site_id=site["site_id"]).cgx_content["tags"]
                                    if tags:
                                        for item in tags:
                                            if item == "alert_ignore":
                                                ignore=True
                                    if not ignore:
                                        circuit_data["alert"] = True
                                        circuit_data["active"] = True
                                        circuit_data["active_count"] = 1
                                        
                                        active_found = False
                                        for index in range(len(circuit_list)):
                                            if circuit_data["path_id"] == circuit_list[index]["path_id"] and circuit_data["direction"] == circuit_list[index]["direction"]:
                                                circuit_list[index]["active"] = True
                                                circuit_list[index]["active_count"] += 1
                                                active_found = True
                                        if not active_found:
                                            circuit_list.append(circuit_data)
                                    else:
                                        print("Ignoring alerts for site " + site_name)
                                        logger.info("Ignoring alerts for site " + site_name)
                                        circuit_list_ignore.append(path["path_id"])
                            except:
                                print("Failed")
    
    message_new = ""
    message_active = ""
    circuit_list_update = []
    for index in range(len(circuit_list)):
        if circuit_list[index]["active"] == False:
            print("Removing circuit alarm for site:" + circuit_list[index]["site_name"] + " path: " + circuit_list[index]["path_id"])
        elif circuit_list[index]["path_id"] in circuit_list_ignore:
            print("Removing ignored circuit alarm for site:" + circuit_list[index]["site_name"] + " path: " + circuit_list[index]["path_id"])
        else:
            if circuit_list[index]["alert"]:
                message_new += "\n" + str(circuit_list[index])
                circuit_list[index]["alert"] = False
                circuit_list_update.append(circuit_list[index])
            
            elif circuit_list[index]["active_count"] > 24:
                circuit_list[index]["active_count"] = 1
                message_new += "\n" + str(circuit_list[index])
                circuit_list_update.append(circuit_list[index])
            
            else:
                message_active += "\n" + str(circuit_list[index])
                circuit_list_update.append(circuit_list[index])
    
    circuit_list = circuit_list_update.copy()
    print("############ New Alerts ##############") 
    if message_new != "":
        mail_subject = "Prisma SD-WAN New Circuit Alerts"
        mail_body = message_new
        logger.info(mail_body)
        print(mail_body)
        send_email(mail_body, mail_subject)
    else:
        print("No new alerts")
    print("######################################")
    print("########## Active Alerts #############") 
    if message_active != "":
        mail_subject = "Prisma SD-WAN Exsiting Circuit Alerts"
        mail_body = message_active
        logger.info(mail_body)
        print(mail_body)
        send_email(mail_body, mail_subject)
    else:
        print("No active alerts")
    print("######################################")  
    return
    

def send_email(mail_body, mail_subject):
    try:
        mimemsg = MIMEMultipart()
        mimemsg['To']=EMAIL_TO
        mimemsg['From']=EMAIL_FROM
        mimemsg['Subject']=mail_subject
        mimemsg.attach(MIMEText(mail_body, 'plain'))
        connection = smtplib.SMTP(host='smtp.office365.com', port=587)
        connection.starttls()
        connection.login(EMAIL_FROM,EMAIL_PASSWORD)

        connection.send_message(mimemsg)
        connection.quit()
        print("Email sent to " + EMAIL_TO)
        logger.info("Email sent to " + EMAIL_TO)
    except Exception as e:
        print(str(e))
        message = "Failed to send email " + mail_subject + " to " + EMAIL_TO
        print(message)
        logger.info(message)  
    return

                                          
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    args = vars(parser.parse_args())
                             
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])
    
    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} {1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))


    # check for token
    if CLOUDGENIX_AUTH_TOKEN:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()
    else:
        print("AUTH_TOKEN missing")
        sys.exit()
        

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')
    message = "Starting Circuit Alert Script"
    print(message)
    logger.info(message)

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    schedule.every(60).minutes.do(run_reports, cgx)
    while True:
        schedule.run_pending()
        time.sleep(30)
    #end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()