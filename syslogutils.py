# implement Re-usable Code from regex101.com Code Generator as a function 
import socket
import re
import yaml 

class Facility:
  """Syslog facilities"""
  KERN, USER, MAIL, DAEMON, AUTH, SYSLOG, \
  LPR, NEWS, UUCP, CRON, AUTHPRIV, FTP = range(12)

  LOCAL0, LOCAL1, LOCAL2, LOCAL3, \
  LOCAL4, LOCAL5, LOCAL6, LOCAL7 = range(16, 24)

class Level:
  """Syslog levels"""
  EMERG, ALERT, CRIT, ERR, \
  WARNING, NOTICE, INFO, DEBUG = range(8)

class Syslog:
  """A syslog client that logs to a remote server.

  Example:
  >>> log = Syslog(host="foobar.example")
  >>> log.send("hello", Level.WARNING)
  """
  def __init__(self,
               host="localhost",
               port=514,
               facility=Facility.DAEMON):
    self.host = host
    self.port = port
    self.facility = facility
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  def send(self, message, level):
    "Send a syslog message to remote host using UDP."
    data = "<%d>%s" % (level + self.facility*8, message)
    self.socket.sendto(data.encode(), (self.host, self.port))

  def warn(self, message):
    "Send a syslog warning message."
    self.send(message, Level.WARNING)

  def notice(self, message):
    "Send a syslog notice message."
    self.send(message, Level.NOTICE)

  def error(self, message):
    "Send a syslog error message."
    self.send(message, Level.ERR)
    
def test_re(regex, test_str, countOnly=False):
    """ Tests Regular Expression on a sample test_string - results by default displayed. 
        if countOnly is True => returns the Count of groups resulted from the regular expression. 
    """
    matches = re.finditer(regex, test_str, re.MULTILINE)
    
    count = 0 
    for matchNum, match in enumerate(matches, start=1):
        if not countOnly:
            print("Matching Syslog.")
        count += 1 

        for groupNum in range(0, len(match.groups())):
            count +=1
            groupNum = groupNum + 1
            if not countOnly:
                print ("Group {groupNum} found: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum)))
    
    if count == 0 and not countOnly: 
        print("Not a matching Syslog!")
    elif count == 0 and countOnly: 
        return 0 
    elif countOnly: 
        return count-1
    
def getVars(msg, left_delimiter = '<<', right_delimiter=">>"):
    """Extract Variables found in Delimiters within an msg String and returns their list."""
    msgList = msg.split(left_delimiter)
    varList = [] 
    for rem in msgList: 
        if rem.find(right_delimiter)!=-1:  
            varList.append(rem[:rem.find(right_delimiter)])
    finalVarList = []
    for _var in varList:
        if _var =='ip' or _var =='mac':
            finalVarList.append("$"+_var)
        else: 
            finalVarList.append("$fsapi_"+"_".join(_var.lower().split(' ')))
    return finalVarList

def getProps(msg, left_delimiter = '<<', right_delimiter=">>"):
    """Extract Variables found in Delimiters within an msg String and returns their list - except ip / mac."""
    msgList = msg.split(left_delimiter)
    varList = [] 
    for rem in msgList: 
        if rem.find(right_delimiter)!=-1:  
            varList.append(rem[:rem.find(right_delimiter)])
    finalVarList = []
    for _var in varList:
        if _var =='ip' or _var =='mac':
            pass
        else: 
            finalVarList.append("_".join(_var.lower().split(' ')))
    return finalVarList

class syslogConfig(object):
    
    def __init__(self, appName):
        self.appName = appName
        self.dexProps = []
        self.initConfig()
    
    def initConfig(self):
        self.finalized = False
        config = ""
        appName = self.appName
        appNameLower = appName.lower()
        self.apptype = "_".join(appNameLower.split())
        for i in range(3):
            configLine = f'fstool syslog set_property config.type{i+1}.option.{self.apptype} "{self.appName}"'
            config += configLine + "\n"
        config += "fstool service restart\n"
        self.config = config
    
    def config(self):
        return self.config
    
    def setOnline(self, propName, status=True):
        #fstool syslog set_property template.pulse_vpn_traps_vpn_login.set_true = \$online
        _propName = "_".join(propName.lower().split(" "))
        _prefix = f"template.{_propName}"
        
        if status: 
            _cmd = 'set_true'
        else: 
            _cmd = 'set_false'
        
        _propConf = f'fstool syslog set_property {_prefix}.{_cmd} "\\$online"'
        _propConf +='\n'
        self.config += _propConf
        print(f"$online status set to {status} for {propName}")
        
        
    def add(self, propName, prop_regex, prop_syslog, prop_msg):
        _propName = "_".join(propName.lower().split(" "))
        _prefix = f"template.{_propName}"
        _vars = getVars(prop_syslog)
        if test_re(prop_regex, prop_msg, countOnly=True) != len(_vars):
            print("Error! Regular Expression applied on that sample message does not produce the expected number of properties!")
            test_re(prop_regex, prop_msg, countOnly=False)
            print(f"While you have identified {len(_vars)} fields!")
            print(_vars)
            return False 
        
        _dexProps = getProps(prop_syslog)
        if len(_dexProps) > 0: 
            for _dexProp in _dexProps:
                self.dexProps.append(_dexProp)
            
        _varStr = ""
        for _var in _vars:
            _varStr+=_var+","
            
        _propConf ="\n"
        _propConf += f'fstool syslog set_property {_prefix}.type "{self.apptype}"'
        _propConf +="\n"
        _propConf += f'fstool syslog set_property {_prefix}.regexp "{prop_regex}"'
        _propConf +="\n"
        _propConf_special = f'fstool syslog set_property {_prefix}.properties  "{_varStr[:-1]}"'
        _propConf_special = _propConf_special.replace('$','\\$')
        _propConf += _propConf_special
        _propConf +="\n"
        
        self.config += _propConf
        
        print(f"Correctly added the Property for {propName}")
        
    def writeDexProperties(self, dex_user, _fName):
        _xmlFinal = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
        <EDS_PROPERTY_ROOT>"""

        for prop in self.dexProps: 
            print(f"Generating dexProperties for: {prop}")
            _xmlNode = f"""<EDS_PROPERTY ID="fsapi_{prop}" eds_display_property_in_inventory="true" eds_display_property_in_inventory_description="Real-time Inventory of {prop}" eds_property_composite="false" eds_property_description="" eds_property_is_MAC="false" eds_property_is_aggregator="false" eds_property_is_list="false" eds_property_is_show_in_portal="true" eds_property_is_show_in_profile="true" eds_property_is_track_changes="true" eds_property_label="{prop}" eds_property_name="fsapi_{prop}" eds_property_server_type="WEB" eds_property_track_changes_description="Indicates a change in the {prop} property" eds_property_track_changes_label="{prop} Change" eds_property_type="string">
            <EDS_DEVICE_KEY_PROPERTY CATEGORY="eds_integration" KEY="{dex_user}" PROPERTY_NAME="eds_property_integration"/>
        </EDS_PROPERTY>"""
            _xmlFinal+="\n"
            _xmlFinal+= _xmlNode
        _xmlFinal += "\n"
        _xmlFinal += "</EDS_PROPERTY_ROOT>"

        print(f"Writing DEX Properties to file: {_fName}")
        try: 
            f = open(_fName, "w")
            f.write(_xmlFinal)
            f.close()
        except: 
            print(f"Error While writing to file: {_fName}")
            return False

        return True

    def finalConfig(self, em=False):
        if not self.finalized: 
            self.config += "fstool syslog restart\n"
            self.finalized = True 
            
        if not em: 
            return self.config
        confList = self.config.split("\n")
        newConfList = []
        for _confItem in confList:
            if _confItem.find('fstool')!=-1: 
                newConfList.append(f'fstool oneach {_confItem}')
            else: 
                newConfList.append(_confItem)
        return "\n".join(newConfList)