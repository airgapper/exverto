
#Python Built-in Library
import re


#External Python Mods
import ipaddress
from flask import request # for request.args.get
import random # for randomMAC


class Helpers:

    def __init__(self, *arg):
        super(Helpers, self).__init__()
        self.arg = arg

    def _resolve_remote_addr():
            if request.environ.get('HTTP_X_FORWARDED_FOR') is not None:
                x_forwarded_for = request.environ['HTTP_X_FORWARDED_FOR'].split(',')
                addr = x_forwarded_for[0]
                try:
                    ipaddress.ip_address(addr)
                    return addr
                except:
                    pass

            return request.remote_addr



###############################
###############################
##        NOT USED YET       ##
###############################






    def randomMAC():
        """Generate a random MAC address."""
        # qemu MAC
        oui = [0x52, 0x54, 0x00]
        mac = oui + [random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))


    def randomUUID():
        """Generate a random UUID."""
        u = [random.randint(0, 255) for dummy in range(0, 16)]
        return "-".join(["%02x" * 4, "%02x" * 2, "%02x" * 2, "%02x" * 2, "%02x" * 6]) % tuple(u)


    def xml_escape(str):
        """Replaces chars ' " < > & with xml safe counterparts"""
        if str is None:
            return None

        str = str.replace("&", "&amp;")
        str = str.replace("'", "&apos;")
        str = str.replace("\"", "&quot;")
        str = str.replace("<", "&lt;")
        str = str.replace(">", "&gt;")
        return str


    def clean_name(self):
    		if not re.match(r'^[a-zA-Z0-9]+$', self.cleaned_data['name']):
    			raise ValidationError(_('Name contains illegal characters'))
    		return self.cleaned_data['name'].lower()


    def _clean_input(self, inp):
            """Clean the input string of anything not plain alphanumeric chars,
            return the cleaned string."""
            return self.clean_input_re.sub('', inp).strip()

    remove_empty_line = lambda s: "\n".join(filter(lambda x:len(x)>0, s.replace("\r\n","\n").replace("\r","\n").split("\n")))

    # IPV4_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/;
    # IPV6_REGEX = /^(?:(?:[a-fA-F\d]{1,4}:){7}(?:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,2}|:)|(?:[a-fA-F\d]{1,4}:){4}(?:(?::[a-fA-F\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,3}|:)|(?:[a-fA-F\d]{1,4}:){3}(?:(?::[a-fA-F\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,4}|:)|(?:[a-fA-F\d]{1,4}:){2}(?:(?::[a-fA-F\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,5}|:)|(?:[a-fA-F\d]{1,4}:){1}(?:(?::[a-fA-F\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,6}|:)|(?::(?:(?::[a-fA-F\d]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,7}|:)))(?:%[0-9a-zA-Z]{1,})?$/;

    ASN_MIN = 0;
    ASN_MAX = 4294967295;

    def clean_ipv4_addr(self):
        ipv4_addr = self.cleaned_data['ipv4_addr']
        have_symbol = re.match('[^0-9./]+', ipv4_addr)
        if have_symbol:
            raise forms.ValidationError(_('The ipv4 must not contain any special characters'))
        elif len(ipv4_addr) > 20:
            raise forms.ValidationError(_('The ipv4 must not exceed 20 characters'))
        return ipv4_addr

    # def nullOrEmpty(obj):
    #         if obj == undefined || obj == null || obj == '';
    #         return

    # def checkAsn(asn):
    #     if (nullOrEmpty(asn)) return false;
    #         const _asn = Number(asn);
    #         if (isNaN(_asn) || _asn < ASN_MIN || _asn > ASN_MAX) return false;
    #         return true;


    def compareMAC(p, q):
        """Compare two MAC addresses"""
        pa = p.split(":")
        qa = q.split(":")

        if len(pa) != len(qa):
            if p > q:
                return 1
            else:
                return -1

        for i in xrange(len(pa)):
            n = int(pa[i], 0x10) - int(qa[i], 0x10)
            if n > 0:
                return 1
            elif n < 0:
                return -1
        return 0



    def pretty_mem(val):
        val = int(val)
        if val > (10 * 1024 * 1024):
            return "%2.2f GB" % (val / (1024.0 * 1024.0))
        else:
            return "%2.0f MB" % (val / 1024.0)



    def proccess_data(data_in):
        ret_dict = {}
        for data_in_item in data_in.split("\n"):
            if len(data_in_item) == 0:
                continue
            if data_in_item[0] == "%":
                continue
            if ":" not in data_in_item:
                continue
            key , val = data_in_item.split(":",1)
            val = val.lstrip()
            if key in ret_dict:
                ret_dict[key] = [val] + ret_dict[key]
            else:
                ret_dict[key] = [val]
        return ret_dict


    # def _parse_whois(output: str, targets: List[str]) -> Dict[str, str]:
    #     data = {}
    #
    #     for line in lines(output):
    #         print(line)
    #         # Unpack each line's parsed values.
    #         asn, ip, prefix, country = line
    #
    #         # Match the line to the item in the list of resources to query.
    #         if ip in targets:
    #             i = targets.index(ip)
    #             data[targets[i]] = {
    #                 "asn": asn,
    #                 "ip": ip,
    #                 "prefix": prefix,
    #                 "country": country,
    #             }
    #     log.debug("Parsed bgp data: {}", data)
    #     return data




    def _lines(raw):
        """Generate clean string values for each column."""
        for r in (r for r in raw.split("\n") if r):
            fields = (
                re.sub(r"(\n\r)", "", field).strip(" ") for field in r.split("|")
            )
            yield fields
