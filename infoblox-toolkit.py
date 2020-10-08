import time
import requests
import json
import platform
import getpass
requests.packages.urllib3.disable_warnings()
import os

infoblox_url = 'https://somehwere.net'

class infoblox(object):
    def __init__(self):
        self.ib_wapi_version = 'v2.2.2'
        self.ib_base_url = infoblox_url
        self.ib_url = '{}/wapi/{}/'.format(self.ib_base_url, self.ib_wapi_version)

    def load_credentials(self, json_filename):
        with open('{}'.format(json_filename), 'r') as ipam_creds:
            ipam = json.load(ipam_creds)
            self.ipam_user = ipam['user']
            self.ipam_password = ipam['password']
        self.ib_session()

    def load_credentials_general(self, ipam_user, ipam_password):
        self.ipam_user = ipam_user
        self.ipam_password = ipam_password
        self.ib_session()
    def load_creds_quick(self, creds_json_filename):
        with open(creds_json_filename, 'r') as ssh_config:
            sc = json.load(ssh_config)
            self.ipam_user = sc['SSH_User']['username']
            self.ipam_password = sc['SSH_User']['password']
        self.ib_session()

    def load_credentials_jenkins(self):
        self.ipam_user = os.environ['SSH_User']
        self.ipam_password = os.environ['SSH_Pass']
        self.ib_session()

    def ib_session(self):
        session = requests.Session()
        session.auth = (self.ipam_user, self.ipam_password)
        session.verify = False
        self.session = session

    def ib_kill_session(self):
        self.session.close()

    def put_r(self, ref_obj, data):
        r = self.session.put(self.ib_url+ref_obj, json=data)
        return r

    def post_r(self, json_data):
        r = self.session.post(self.ib_url+'request', json=json_data)
        return r

    def post_r_url(self, ext_url):
        r = self.session.post(self.ib_url+ext_url)
        return r

    def get_r(self, ext_url):
        r = self.session.get(self.ib_url+ext_url)
        return r

    def delete_r(self, ref_obj):
        r = self.session.delete(self.ib_url+ref_obj)
        return r

    def ib_get_record_host(self, hostname):
        ext_url = 'record:host?name~={}'.format(hostname)
        r = self.get_r(ext_url)
        return r

    def ib_get_record_host_evaluator(self, evaluator, hostname):
        ext_url = 'record:host?name{}{}'.format(evaluator, hostname)
        r = self.get_r(ext_url)
        return r

    def ib_get_record_cname_evaluator(self, evaluator, hostname):
        ext_url = 'record:cname?name{}{}'.format(evaluator, hostname)
        r = self.get_r(ext_url)
        return r

    def ib_get_wapi_object_w_evaluator(self, wapi_object, evaluator, hostname):
        ext_url = '{}{}{}'.format(wapi_object, evaluator, hostname)
        r = self.get_r(ext_url)
        return r

    def ib_get_network_from_network(self, network):
        ext_url = 'network?network=' + network
        r = self.get_r(ext_url)
        return r

    def ib_get_ipv4addresses_from_subnet(self, subnet):
        ext_url = 'ipv4address?network={}'.format(subnet)
        r = self.get_r(ext_url)
        return r

    def ib_get_network_from_network_container(self, network_container):
        ext_url = 'network?network_container=' + network_container
        r = self.get_r(ext_url)
        return r

    def ib_ipv4address_lookup(self, ip):
        ext_url = 'ipv4address?ip_address='+ip
        r = self.get_r(ext_url)
        return r

    def ib_ipv4address_update_attr(self, ip, data):
        r = ipv4address_lookup(ip)
        json_loads = json.loads(r.text)
        ref_obj = json_loads[0]['objects'][0]
        actionVerb = ref_obj
        r = self.get_put(actionVerb, data)
        return r

    def ib_get_extattr(self, extattr_attribute, evaluator, extattr_value):
        actionVerb = 'network?_return_fields%2B=extattrs&*'
        ext_url = '{}{}{}{}'.format(actionVerb, extattr_attribute, evaluator, extattr_value)
        r = self.get_r(ext_url)
        return r

    def ib_get_security_zone(self, evaluator, zone_value):
        r = self.ib_get_extattr('Security_Zone', evaluator, zone_value)
        return r

    def ib_get_ref_url_from_string(self, string):
        url_refs = []
        r = self.get_r('search?search_string~=' + string)
        if len(r.json())==0:
            print('Problem finding ref')
            url_ref = None
        elif len(r.json())==1:
            url_ref = r.json()[0]['_ref']
        else:
            for i in r.json():
                if i.get('name',False):
                    url_refs.append(i['_ref'])
                elif i.get('names',False):
                    for n in i['objects']:
                        url_refs.append(n)
                else:
                    print('not sure')
            # print '2 entries found...'
        if len(url_refs)>0:
            return url_refs
        else:
            return url_ref

    def get_a_records_by_devicetype(name,devicetype="STATIC"):
        search_device = ('name~=' + name)
        query = 'record:a?_return_type=json-pretty&{}&creator={}'.format(search_device,devicetype)
        r = get_r(self.ib_url + query)
        return r

    def create_data_record_host(self,hostname,ip):
        data=[{
            "method":"POST",
            "object":"record:host",
            "data": {
            "name":hostname,
            "ipv4addrs":[
                {"ipv4addr":ip}
                ]
            }
        }]
        return data

    def create_network_from_network_object(self, network_object):
        site_code = network_object['site_code']
        bgp_as = network_object['bgp_as']
        subnet = network_object['subnet']
        vlan_name = network_object['vlan_name']
        member_servers = network_object['member_servers']
        discovery_node = network_object['discovery_node']
        domain_name = network_object['domain_name']
        router_address = '.'.join(subnet.split('.')[0:3])+'.'+str(int(subnet.split('.')[3].split('/')[0])+1)
        broadcast_address = str(ipaddress.IPv4Interface(u'{}'.format(subnet)).network.broadcast_address)
        member_list=[]
        if len(member_servers) == 1:
            member_list = [{
                "_struct": "dhcpmember",
                "name" : member_servers[0]
            }]
        else:
            member_list = []
            for member_server in member_servers:
                member_list.append({"_struct": "dhcpmember","name" : member_server})
        data=[{
            "method":"POST",
            "object":"network",
            "data": {
            "network": subnet,
            "comment": vlan_name,
            "discovery_member": discovery_node,
            "enable_discovery": True,
            "extattrs":{
                    "Site":{"value":site_code.upper()},
                    "BGP_AS":{"value":str(bgp_as)}
                },
            "options":[
                {'name':'domain-name-servers','value':'172.30.0.10'},
                {'name':'routers','value':router_address},
                {'name':'domain-name','value':domain_name},
                {'name':'broadcast-address','value':broadcast_address}
                ]
            }
        }]
        if len(member_list)>0:
            data[0]['data']['members'] = member_list
        return data

    # def get_r_payload(self, payload):
    #     r = self.session.get(self.ib_url, params=payload)
    #     return r
def ib_main():
    ibi_r = infoblox()
    if 'Darwin' in platform.platform():
        creds_json_filename_w_path = (os.path.expanduser('~')+'/.creds.json')
        ibi_r.load_creds_quick(creds_json_filename_w_path)
        # username = raw_input('Username:')
        # password = getpass.getpass()
        # ibi_r.load_credentials_general(username,password)
    else:
        ibi_r.load_credentials_jenkins()
    return ibi_r

