-- Split trace based on SCCP Source
do
        local function init_listener()
                print("CREATED LISTENER")
		local tap = Listener.new("ip", "sccp && (ip.src == 172.16.1.81 || ip.dst == 172.16.1.81)")
		local sccp_type_field = Field.new("sccp.message_type")
		local sccp_src_field = Field.new("sccp.slr")
		local sccp_dst_field = Field.new("sccp.dlr")
		local msg_type_field = Field.new("gsm_a.dtap_msg_mm_type")
		local lu_rej_field = Field.new("gsm_a.dtap.rej_cause")
		local ip_src_field = Field.new("ip.src")
		local ip_dst_field = Field.new("ip.dst")

		local connections = {}

		function check_failure(con)
			local msg_type =  msg_type_field()
			if not msg_type then
				return
			end

			msg_type = tonumber(tostring(msg_type))
			if msg_type == 0x04 then
				print("LU REJECT with " .. tostring(lu_rej_field()))
				con[4] = true
			end
		end

                function tap.packet(pinfo,tvb,ip)
			local ip_src = tostring(ip_src_field())
			local ip_dst = tostring(ip_dst_field())
			local sccp_type = tonumber(tostring(sccp_type_field()))
			local sccp_src = sccp_src_field()
			local sccp_dst = sccp_dst_field()

			local con

			if sccp_type == 0x01 then
			elseif sccp_type == 0x2 then
				local src = string.format("%s-%s", ip_src, tostring(sccp_src))
				local dst = string.format("%s-%s", ip_dst, tostring(sccp_dst))
				local datestring = os.date("%Y%m%d%H%M%S")
				local pcap_name = string.format("alink_trace_%s-%s_%s.pcap", src, dst, datestring)
				local dumper = Dumper.new_for_current(pcap_name)

				local con = { ip_src, tostring(sccp_src), tostring(sccp_dst), false, dumper, pcap_name }

				dumper:dump_current()
				connections[src] = con
				connections[dst] = con
			elseif sccp_type == 0x4 then
				-- close a connection... remove it from the list
				local src = string.format("%s-%s", ip_src, tostring(sccp_src))
				local dst = string.format("%s-%s", ip_dst, tostring(sccp_dst))

				local con = connections[src]
				if not con then
					return
				end

				con[5]:dump_current()
				con[5]:flush()

				-- this causes a crash on unpacted wireshark
				con[5]:close()

				-- the connection had a failure
				if con[4] == true then
					local datestring = os.date("%Y%m%d%H%M%S")
					local new_name = string.format("alink_failure_%s_%s-%s.pcap", datestring, con[2], con[3])
					os.rename(con[6], new_name)
				else
					os.remove(con[6])
				end


				-- clear the old connection
				connections[src] = nil
				connections[dst] = nil

			elseif sccp_type == 0x5 then
				-- not handled yet... we should verify stuff here...
				local dst = string.format("%s-%s", ip_dst, tostring(sccp_dst))
				local con = connections[dst]
				if not con then
					return
				end
				con[5]:dump_current()
			elseif sccp_type == 0x6 then
				local dst = string.format("%s-%s", ip_dst, tostring(sccp_dst))
				local con = connections[dst]
				if not con then
					print("DON'T KNOW THIS CONNECTION for " .. ip_dst)
					return
				end
				con[5]:dump_current()
				check_failure(con)
			end

                end
                function tap.draw()
                        print("DRAW")
                end
                function tap.reset()
                        print("RESET")
                end
        end

        init_listener()
end
