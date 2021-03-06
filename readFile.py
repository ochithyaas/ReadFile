# chanaka
# HELLO
# Formats the flow descript of the ip address
# ip_address: string that contains the ip_address
# ip_count: integer that contains the current number of seen ip addresses
def format_flow_description(ip_address, ip_count):
    return '\tflow-description ' + str(ip_count) + '\n' + '\t\tmatch\n' + '\t\t\t remote-ip ' + ip_address + '\n' + '\t\texit\n' + '\texit\n'

# Formats the urls to the write output
def format_url(line):
    url = line.split(' ')[-1]
    url = url.replace('https://','')
    url = url.replace('http://','')
    if url == '':
        return None
    if line.startswith('www'):
        if url[-1].isdigit():
            return '\t\tserver-address eq ' + url + '\n'
        else:
            return '\t\texpression 1 http-host eq \"^' + url + '$\"\n'
    elif line.startswith('p2p'):
        return '\t\texpression 1 tls-cert-subj-common-name eq "*.' + url + '$\"\n'
    return '\t\texpression 1 '  + ' http-host eq ' + url + '\n'

def tcp_udp_format(tcp_ports, udp_ports, ruledef_name):
    ret = ''
    if len(tcp_ports) != 0:
        ret += 'port-list ' + ruledef_name + '-tcp\n'
        for tcp in tcp_ports:
            if ' = ' in tcp:
                port = tcp.split(' = ')[-1]
                ret += '\tport ' + port + '\n'
            elif ' range ' in tcp:
                range = tcp.split(' to ')
                high = range[-1]
                low = range[0].split(' ')[-1]
                ret += '\tport range ' + low + ' ' + high + '\n'
        ret += 'exit\n\n'
    if len(udp_ports) != 0:
        ret += 'port-list ' + ruledef_name + '-udp\n'
        for udp in udp_ports:
            if ' = ' in udp:
                port = udp.split(' = ')[-1]
                ret += '\tport ' + port + '\n'
            elif ' range ' in udp:
                range = udp.split(' to ')
                high = range[-1]
                low = range[0].split(' ')[-1]
                ret += '\tport range ' + low + ' ' + high + '\n'
        ret += 'exit\n\n'
    count = 1
    ret += 'policy-rule-unity \"' + ruledef_name + '\"\n'
    if len(tcp_ports) != 0:
        ret += '\tflow-description ' + str(count) + '\n' + '\t\tmatch\n\t\tprotocol 6\n\t\t\tremote-port-list '+ ruledef_name +'-tcp\n\t\texit\n\texit\n'
        count+=1
    if len(udp_ports) != 0:
        ret += '\tflow-description ' + str(count) + '\n' + '\t\tmatch\n\t\tprotocol 17\n\t\t\tremote-port-list '+ ruledef_name +'-udp\n\t\texit\n\texit\n'
        count+=1
    # ret += 'exit\n'
    return ret
# input_file = open('INPUT FILE NAME OR PATH', 'r') # the first argument is the file name and the second argument says you want to read the file only
# output_file = open('OUTPUT FILE NAME OR PATH', 'w') # The 'w' is for overwriting a file. So if it contains stuff it will be overwritten
                                                            # If you don't want to overwrite you can use 'a' to append to the existing file instead
                                                            # Also if you are creating a new file and you do not want it to currently exist then use 'x'

input_file = open('SEPCF010_ecs.log', 'r')
output_file = open('smf.cfg', 'w')
output_file2 = open('upf-aa.cfg','w')
output_file3 = open('upf.cfg','w')
input_file_array = input_file.read().split('\n')
start_search = False
ip_address_count = 1 # used to count the ip_addresses
entry = 6000
sru_id = 1
pdr_id = 1
ruledefs_list = [] # get the ruledefs of the rulebase action priorities
rulebase_name = '' # get the rulebase_name
start_action_priority_search = False
start_charge_action_search = False
start_x_header_search = False
start_host_pool = False
ip_address = ''
idx_input_file = 0
ip = False
tcp_ports = []
udp_ports = []
while idx_input_file < len(input_file_array):
    line = input_file_array[idx_input_file].strip() # Removes all trailing spaces

    if start_host_pool:
        if line.startswith('ip') and '/' in line:
            ip_and_mask = line.split(' ')[-1].split('/')
            ip = ip_and_mask[0]
            mask = ip_and_mask[1]
            output_file.write('\taddress ' + ip + ' #mask ' + mask  + '\n')
            output_file3.write('\taddress ' + ip + ' #mask ' + mask  + '\n')
            output_file.flush()
            output_file3.flush()
        if line.startswith('#exit'):
            output_file.write('exit\n')
            output_file3.write('exit\n')
            output_file.flush()
            output_file3.flush()
            start_host_pool = False
    elif line.startswith('host-pool'):
        host_pool_name = line.split(' ')[-1]
        output_file.write('ip-address-list ' + host_pool_name + '\n')
        output_file3.write('ip-address-list ' + host_pool_name + '\n')
        output_file.flush()
        output_file3.flush()
        start_host_pool = True

    elif start_charge_action_search:
        if line.startswith('content-id'):
            rating_group = line.split(' ')[-1]
            output_file.write('\trating-group ' + rating_group + ' sru ' + str(sru_id) +'\n')
        if line.startswith('service-identifier'):
            output_file.write('\t' + line + '\n')
        if line.startswith('#exit'):
            output_file.write('exit\n\n')
            start_charge_action_search = False
    elif line.startswith('charging-action'):
        chargingaction_name = line.split(' ')[-1]
        output_file.write('stat-rule-unit \"' + str(sru_id) + '\"\n')
        output_file.write('\turr-id ' + str(sru_id) + ' urr-profile fpt' + '\n')
        output_file.write('exit\n\n')
        output_file3.write('stat-rule-unit \"' + str(sru_id) + '\"\n')
        output_file3.write('\turr-id ' + str(sru_id) + ' urr-profile fpt' + '\n')
        output_file3.write('exit\n\n')
        output_file.write('charging_rule_unit \"' + chargingaction_name + '\"\n')
        output_file3.write('sru-list \"' + chargingaction_name + '\"\n')
        output_file3.write('\tstat-rule-unit \"' + str(sru_id) + '\"\n')
        output_file3.write('exit\n\n')
        start_charge_action_search = True
        sru_id+=1


    elif start_x_header_search:
        if line.startswith('insert') and 'bearer ' in line:
            insert_line = line.split(' ')
            name = insert_line[1]
            idx = insert_line.index('bearer')
            field = ' '.join(insert_line[idx+1::])
            output_file2.write('\tfield \"' + field + '\"\n\t\tname \"'+name+'\"\n\texit\n')
        elif line.startswith('#exit'):
            output_file2.write('\tno shutdown\nexit\n\n')
            start_x_header_search = False
    elif line.startswith('xheader-format'):
        start_x_header_search = True
        xheader = line.split(' ')[-1]
        output_file2.write('http-enrich \"' + xheader + '\" create\n')
        output_file2.flush()

    elif start_action_priority_search:
        if line.startswith('action priority'):

            # grab the necessary info from the line
            action_priority_array = line.split(" ")
            precedence = action_priority_array[2]
            action_ruledef = ''
            if 'ruledef' in action_priority_array:
                idx_ruledef = action_priority_array.index('ruledef')
                action_ruledef = '\"' + action_priority_array[idx_ruledef+1] + '\" '
            else:
                idx_ruledef = action_priority_array.index('group-of-ruledefs')
                action_ruledef = '\"' + action_priority_array[idx_ruledef + 1] + '\" '
            # action_ruledef = '\"' + action_priority_array[4] + '\" '
            ruledefs_list.append(action_ruledef) # for th
            charging_action = '\" '+ action_priority_array[-1] + ' \" '

            # write the policy rule to the output file
            output_file.write('policy-rule ' + action_ruledef +
                                'policy-rule-unit ' + action_ruledef +
                                'charging-rule-unit ' + charging_action +
                                'qci * arp * precedence ' + precedence + '\n')
            output_file3.write('policy-rule ' + action_ruledef +
                                'policy-rule-unit ' + action_ruledef +
                                'stat-rule-unit-list ' + charging_action +
                                'qci * arp * precedence ' + precedence + '\n')

        elif line.startswith('#exit'):
            # write the policy rule base to the output file
            output_file.write('\npolicy-rule-base ' + rulebase_name + '\n')
            output_file3.write('\npolicy-rule-base ' + rulebase_name + '\n')
            for rd in ruledefs_list:
                output_file.write('\tpolicy-rule ' + rd + '\n')
                output_file3.write('\tpolicy-rule ' + rd + '\n')
            output_file.write('exit\n\n')
            output_file3.write('exit\n\n')
            output_file.flush()
            output_file3.flush()
            rulebase_name = ''
            start_action_priority_search = False

    elif line.startswith('rulebase'):
        rulebase_name = '\"' + line.partition('rulebase ')[2] + '\"'
        start_action_priority_search = True

    elif start_search: # You've seen a ruledef so now search for ip addresses and urls
        # search for ip_addresses
        if line.startswith('ip server-ip-address') and input_file_array[idx_input_file+1].strip().startswith('tcp') == False:

            ip_address = line.split(' ')[-1] # extract the ip-address fromt the input line

            output_file.write(format_flow_description(ip_address, ip_address_count))
            output_file3.write(format_flow_description(ip_address, ip_address_count))
            output_file.flush()
            output_file3.flush()

            ip_address_count+=1 #increment the ip_address_count
        elif line.startswith('tcp either-port'):
            tcp_ports.append(line)
        elif line.startswith('udp either-port'):
            udp_ports.append(line)

        elif line.startswith('ip server-ip-address') and input_file_array[idx_input_file+1].strip().startswith('tcp'):
            ip_address = line.split(' ')[-1] # extract the ip-address fromt the input line
            tcp_array = input_file_array[idx_input_file+1].split(' ')
            ports = tcp_array[-1]
            ports_array = []
            if '/' in ports:
                ports_array = ports.split('/')
            else:
                ports_array.append(ports)
            for port in ports_array:
                output_file.write('\tflow-description ' + str(ip_address_count) + '\n' + '\t\tmatch\n\t\t\tprotocol 6\n' + '\t\t\tremote-ip ' + ip_address + '\n' + '\t\t\tport ' + port + '\n\t\texit\n' + '\texit\n')
                output_file3.write('\tflow-description ' + str(ip_address_count) + '\n' + '\t\tmatch\n\t\t\tprotocol 6\n' + '\t\t\tremote-ip ' + ip_address + '\n' + '\t\t\tport ' + port + '\n\t\texit\n' + '\texit\n')
                ip_address_count+=1
        # search for urls
        elif line.startswith('www') or line.startswith('p2p') or line.startswith('http'):
            # url = line.split(' ')[-1] # extract the url from the input line
            url = format_url(line)
            if url == None:
                idx_input_file+=1
                continue
            output_file2.write('\tentry ' + str(entry) + ' create' + '\n')
            output_file2.write('\t\tdescription ' + ruledef_name + '\n')
            output_file2.write(url)
            # output_file.write('\t\texpression 1 '  + ' http-host eq ' + url + '\n')
#            output_file.write('\t\t\t' + url + '\n') # write it into the file so there's a tab at the front and then start a newline
            output_file2.write('\t\tapplication ' + ruledef_name +  '\n')
            output_file2.write('\t\tno shutdown ' + '\n')
            output_file2.write('\t\texit\n')
#            output_file.write('\texit\n')
            output_file2.flush()
            ip_address_count+=1 #increment the ip_address_count
            entry+=1

        elif '#exit' in line: # stop searching for urls and ip-addresses
            if len(udp_ports) != 0 and len(tcp_ports) != 0:
                output_file.write(tcp_udp_format(tcp_ports, udp_ports, ruledef_name))
                output_file3.write(tcp_udp_format(tcp_ports, udp_ports, ruledef_name))
            if ip:
                output_file.write('exit\n\n')
                output_file3.write('exit\n\n')
            else:
                output_file.write('exit\n\n')
                output_file3.write('exit\n\n')
            start_search = False
            ip = False
            ip_address_count = 1 # reset the ip_address_count
            tcp_ports = []
            udp_ports = []

    elif line.startswith('ruledef'):
        # split ruledef line to get the rest of the line
        ruledef_name = line.partition('ruledef ')[2]
        if input_file_array[idx_input_file+1].strip().startswith('ip server-ip-address'):
            output_file.write('policy-rule-unit \"' + ruledef_name + '\"\n')
            output_file.write('\tpdr-id ' + str(pdr_id) + '\n')
            output_file3.write('policy-rule-unit \"' + ruledef_name + '\"\n')
            output_file3.write('\tpdr-id ' + str(pdr_id) + '\n')
            output_file.flush()
            output_file3.flush()
            ip = True
        else:
            output_file.write('\tpolicy-rule-unit \"' + ruledef_name + '\"\n')
            output_file.write('\t\tpdr-id ' + str(pdr_id) + '\n')
            output_file.write('\t\t\tflow-description ' + str(ip_address_count) + '\n')
            output_file.write('\t\t\t\tmatch'  + '\n')
            output_file.write('\t\t\t\t\taa-charging-group '  + ruledef_name + '\n')
            output_file.write('\t\t\t\texit'  + '\n')
            output_file.write('\t\t\texit'  + '\n')
            output_file2.write('\tcharging-group \"' + ruledef_name + '\"'+ ' create' +'\n')
            output_file2.write('\texit'  + '\n')
            output_file2.write('\tapplication \"' + ruledef_name + '\"' +' create' + '\n')
            output_file2.write('\t\tdescription ' + ruledef_name + '\n')
            output_file2.write('\t\tcharging-group ' + ruledef_name + '\n')
            output_file2.write('\texit'  + '\n')
            output_file3.write('\tpolicy-rule-unit \"' + ruledef_name + '\"\n')
            output_file3.write('\t\tpdr-id ' + str(pdr_id) + '\n')
            output_file3.write('\t\t\tflow-description ' + str(ip_address_count) + '\n')
            output_file3.write('\t\t\t\tmatch'  + '\n')
            output_file3.write('\t\t\t\t\taa-charging-group '  + ruledef_name + '\n')
            output_file3.write('\t\t\t\texit'  + '\n')
            output_file3.write('\t\t\texit'  + '\n')
            output_file.flush()
            output_file2.flush()
            output_file3.flush()
            ip = False
            ip_address_count = 1
        # start searching for ip_addresses
        start_search = True
        pdr_id+=1
    idx_input_file+=1
# end_file_string

#close the files
input_file.close()
output_file.close()
output_file2.close()
output_file3.close()
