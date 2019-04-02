#!/bin/bash
# parameters - all must be defined
# 1 = channel - as number - 1 to 4 (normally)
# 2 = show type - nightshow or dayshow

## channelIDs as defined in javascript on site
## 345, // s66 1 // same for nights
## 341, // s66 2
## 343, // s66 3
## 347, // s66 4
## 963, // GG 1 // for nights, state as channel4
## 2701, // GG 2 // for nights, state as channel 3
## 2639, // filth // for nights, state as channel 3
## 2727 // Daytime Xtra
## 6562, // GG 1b / for nights, state as channel4

# functions - begin
function msg_debug()
{
    local debugmsg="$1"
    if [[ ! "${debugmsg}" == "" ]] ; then
		if [[ "${colour,,}" == "true" ]] || [[ "${colour}" == "" ]] ; then
			printf "%s\n" "${c_info}[$(date +%x) $(date +%X)]${c_reset} ${c_error}DEBUG:${c_reset} ${debugmsg}" | tee -a "${log_file}"
		else
			printf "%s\n" "[$(date +%x) $(date +%X)] DEBUG:${debugmsg}" | tee -a "${log_file}"
		fi
    fi
}

function msg_normal()
{
    local normalmsg="$1"
    if [[ ! "${normalmsg}" == "" ]] ; then
		if [[ "${colour,,}" == "true" ]] || [[ "${colour}" == "" ]] ; then
			printf "%s\n" "${c_info}[$(date +%x) $(date +%X)]${c_reset} ${normalmsg}" | tee -a "${log_file}"
		else
			printf "%s\n" "[$(date +%x) $(date +%X)] ${normalmsg}" | tee -a "${log_file}"
		fi
    fi
}

function end_pid()
{
    local run_pid=$1
    kill ${run_pid} &>/dev/null 2>&1
    chkloop=0
}

function tidy_files()
{
    if [[ -f "${filesave}" ]] ; then
		find "${filesave}" -size -${min_file_size} -delete 2>/dev/null
    fi
    if [[ -f "${status_file}" ]] ; then
		rm "${status_file}" 2>/dev/null
    fi
}

function stream_json()
{
    local json_channel=$1
    json_tmp=$(mktemp)
    ${cmd_curl} "${json_url}" --silent --connect-timeout 5 --retry 2 --insecure --fail --noproxy '*' --output "${json_tmp}" 2>/dev/null
    if [[ ! -s "${json_tmp}" ]] ; then
		msg_debug "Failed to download ${json_url}"
		rm "${json_tmp}" 2>/dev/null
		opt_token="null"
		return
    else
		case ${json_channel} in
			1)
				streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."345".streamName')
				if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
				msg_debug "Checking ${json_channel} against channelid 345. Got ${streamName}"
				if [[ "${streamName}" == *"channel1"* ]] ; then
					get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."345".token')
					if [[ "${get_token}" == "" ]] ; then
						msg_debug "Failed to get token for ${json_channel}"
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					else
						opt_token=${get_token}
						opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."345".application')
						opt_channelid=345
						opt_streamName=${streamName}
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				else
					msg_debug "streamName isn't correct for channel ${json_channel}"
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
				;;
	    2)
			streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."341".streamName')
				if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
				msg_debug "Checking ${json_channel} against channelid 341. Got ${streamName}"
				if [[ "${streamName}" == *"channel2"* ]] ; then
					get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."341".token')
					if [[ "${get_token}" == "" ]] ; then
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					else
						opt_token=${get_token}
						opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."341".application')
						opt_channelid=341
						opt_streamName=${streamName}
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				else
					msg_debug "streamName isn't correct for channel ${json_channel}"
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
				;;
	    3)
			if [[ "${showType}" == "DayShow" ]] ; then
				streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."343".streamName')
				if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
				msg_debug "Checking ${json_channel} against channelid 343. Got ${streamName}"
				if [[ "${streamName}" == *"channel3"* ]] ; then
					get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."343".token')
					if [[ "${get_token}" == "" ]] ; then
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					else
						opt_token=${get_token}
						opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."343".application')
						opt_channelid=343
						opt_streamName=${streamName}
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				fi
			else
				streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."2639".streamName')
				if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
					streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."2701".streamName')
					if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					fi
					msg_debug "Checking ${json_channel} against channelid 2701. Got ${streamName}"
					if [[ "${streamName}" == *"channel3"* ]] ; then
						get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."2701".token')
						if [[ "${get_token}" == "" ]] ; then
							opt_token="null"
							rm "${json_tmp}" 2>/dev/null
							return
						else
							opt_token=${get_token}
							opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."2701".application')
							opt_channelid=2701
							opt_streamName=${streamName}
							rm "${json_tmp}" 2>/dev/null
							return
						fi
					else
						msg_debug "streamName isn't correct for channel ${json_channel}"
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				else
					msg_debug "Checking ${json_channel} against channelid 2639. Got ${streamName}"
					if [[ "${streamName}" == *"channel3"* ]] ; then
						get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."2639".token')
						if [[ "${get_token}" == "" ]] ; then
							opt_token="null"
							rm "${json_tmp}" 2>/dev/null
							return
						else
							opt_token=${get_token}
							opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."2639".application')
							opt_channelid=2639
							opt_streamName=${streamName}
							rm "${json_tmp}" 2>/dev/null
							return
						fi
					else
						msg_debug "streamName isn't correct for channel ${json_channel}"
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				fi
			fi
			;;
	    4)
			if [[ "${showType}" == "DayShow" ]] ; then
				streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."347".streamName')
				if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
				msg_debug "Checking ${json_channel} against channelid 347. Got ${streamName}"
				if [[ "${streamName}" == *"channel4"* ]] ; then
					get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."347".token')
					if [[ "${get_token}" == "" ]] ; then
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					else
						opt_token=${get_token}
						opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."347".application')
						opt_channelid=347
						opt_streamName=${streamName}
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				else
					msg_debug "streamName isn't correct for channel ${json_channel}"
					opt_token="null"
					rm "${json_tmp}" 2>/dev/null
					return
				fi
			else
				streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."963".streamName')
				if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
					streamName=$(cat "${json_tmp}" | jq -r '.payload.channelData."6562".streamName')
					if [[ "${streamName}" == "" ]] || [[ "${streamName,,}" == "null" ]] ; then
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					fi
					msg_debug "Checking ${json_channel} against channelid 6562. Got ${streamName}"
					if [[ "${streamName}" == *"channel4"* ]] ; then
						get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."6562".token')
						if [[ "${get_token}" == "" ]] ; then
							opt_token="null"
							rm "${json_tmp}" 2>/dev/null
							return
						else
							opt_token=${get_token}
							opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."6562".application')
							opt_channelid=6562
							opt_streamName=${streamName}
							rm "${json_tmp}" 2>/dev/null
							return
						fi
					else
						msg_debug "streamName isn't correct for channel ${json_channel}"
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				else
					msg_debug "Checking ${json_channel} against channelid 963. Got ${streamName}"
					if [[ "${streamName}" == *"channel4"* ]] ; then
						get_token=$(cat "${json_tmp}" | jq -r '.payload.channelData."963".token')
						if [[ "${get_token}" == "" ]] ; then
							opt_token="null"
							rm "${json_tmp}" 2>/dev/null
							return
						else
							opt_token=${get_token}
							opt_application=$(cat "${json_tmp}" | jq -r '.payload.channelData."963".application')
							opt_channelid=963
							opt_streamName=${streamName}
							rm "${json_tmp}" 2>/dev/null
							return
						fi
					else
						msg_debug "streamName isn't correct for channel ${json_channel}"
						opt_token="null"
						rm "${json_tmp}" 2>/dev/null
						return
					fi
				fi
			fi
			;;
		esac
    fi
    rm "${json_tmp}" 2>/dev/null
}
# functions - end

# check parameters passed
numParams=2
if [[ $# -ne ${numParams} ]] ; then 
    msg_debug "Missing mandatory parameter(s). Exiting..."
	exit 1
fi
channel=$1
recType=$2

# check parameters match needed logic/values
if [[ ! ${channel} = *[[:digit:]]* ]] ; then
	msg_debug "Channel was not a number. Exiting..."
	exit 1
fi
if [[ ${channel} -gt 4 ]] ; then
	msg_debug "Channel number not valid. Exiting..."
	exit 1
fi

if [[ "${recType,,}" == *"day"* ]] ; then
	showType="DayShow"
elif [[ "${recType,,}" == *"night"* ]] ; then
	showType="NightShow"
else
	msg_debug "Show Type not defined correctly (day or night). Exiting..."
	exit 1
fi
start_time=$(date +%s)
if [[ "${showType}" == "DayShow" ]] ; then
	end_time=$(date +%s -d "22:03 today")
elif [[ "${showType}" == "NightShow" ]] ; then
	end_time=$(date +%s -d "05:36 tomorrow")
else
	msg_debug "Show Type duration cannot be set. Exiting..."
	exit 1
fi

# init core variables
site_name=s66tv
base_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
temp_dir="${base_dir}/${site_name}_temp"
if [[ ! -d "${temp_dir%/#}" ]] ; then mkdir -p "${temp_dir%/#}" ; fi
ini_file="${base_dir}/${site_name}.ini"
run_user=$(whoami)
source "${ini_file}"
orig_ini=$(stat --format %Y "${ini_file}")
debug=1
stream_server_len=${#stream_server[@]}
log_file="${base_dir}/${site_name}-stream${channel}-$(date ${date_format}).log"

cmd_record=$(type -P streamlink)
cmd_curl=$(type -P curl)
cmd_jq=$(type -P jq)
# validate elements
for check_file in "${cmd_record}" "${cmd_curl}" "${cmd_jq}"
do
    if [[ ! -f ${check_file} ]] ; then
		msg_debug "Failed to locate required file - missing ${check_file##*/} - exiting..."
		tidy_files
		exit 1
    fi
done

# define colours
if [[ "${colour,,}" == "true" ]] || [[ "${colour}" == "" ]] ; then
	c_error=$'\e[1;31m'    # red
	c_model=$'\e[1;36m'    # cyan
	c_debug=$'\e[1;33m'    # yellow
	c_info=$'\e[0;37m'     # grey
	c_reset=$'\e[0m'       # reset
fi

# keep log files tidy
find ${base_dir} -type f -name ${base_dir}/${site_name}-stream*.log -mtime +2 -delete 2>/dev/null

recordingokay=0
server_num=0
part=1
showDate=$(date +%Y%m%d)

while true
do
	while true
	do
		check_time=$(( end_time - $(date +%s) ))
		if [[ ${check_time} -le 5 ]] ; then 
			end_pid ${run_pid}
			tidy_files
			if [[ ${debug} -eq 1 ]] ; then msg_debug "Timer met - exit recording" ; fi
			exit 0
		fi

		loop_ini=$(stat --format %Y "${ini_file}")
		if [[ ${loop_ini} -gt ${orig_ini} ]] ; then
			if [[ ${debug} -eq 1 ]] ; then msg_debug "${ini_file} has changed - reloading..." ; fi
			source "${ini_file}"
			orig_ini=${loop_ini}
		fi

		opt_od="${recording_dir}/${site_name}/${showType}/"
		if [[ ! -d "${opt_od%/*}" ]] ; then mkdir -p "${opt_od%/*}" ; fi
		
		opt_channel="${long_site_name}-Channel${channel}"
		
		while [[ ${recordingokay} -ne 1 ]]
		do
			filesave="${opt_od}${opt_channel}-${showType}-${showDate}-part$(printf "%02d" ${part}).${fs_type}"
			if [[ -f "${filesave}" ]] ; then
				let part++
				continue
			fi
			stream_json ${channel}
			if [[ ${debug} -eq 1 ]] ; then msg_debug "Returned ${opt_token} ${opt_application} ${opt_mbr} ${opt_streamName}." ; fi
			if [[ "${opt_token}" == "" ]] || [[ "${opt_token,,}" == "null" ]] ; then
				# stream is not live - pause and reloop
				server_num=0
				recordingokay=0
				if [[ ${debug} -eq 1 ]] ; then msg_debug "token was ${opt_token}. Stream ${channel} not live." ; fi
				sleep ${timer_long}s 2>/dev/null
				break 2
			fi
			opt_url="https://${stream_server[${server_num}]}/${opt_application}/smil:${opt_streamName}.smil/playlist.m3u8"
			if [[ "${opt_session_key}" == "" ]] || [[ "${opt_session_key}" == "changeme" ]] ; then
				# assume not logged in, so timeout will occur based on server-side settings
				opt_suffix="channelID=${opt_channelid}&cid=57&customerid=57&token=${opt_token}"
			else
				# assume logged in state, and ini file contains all 3 required parameters
				opt_suffix="channelID=${opt_channelid}&cid=57&customerid=57&token=${opt_token}&ccivrid=${opt_ccivrid}&username=${opt_username}&session_key=${opt_session_key}"
			fi
			# opt_suffix="token=${opt_token}"
			${cmd_record} ${opt_type}://"${opt_url}?${opt_suffix}" ${opt_quality} ${opt_common} --output "${filesave}" ${opt_options} --http-header "${opt_header1}" --http-header "${opt_header2}" &>/dev/null &
			run_pid=$!
			sleep ${timer_medium}s 2>/dev/null
			if [[ -s "${filesave}" ]] ; then 
				msg_normal "Channel ${channel} is recording via server ${stream_server[${server_num}]}..."
				let part++
				recordingokay=1
				break
			fi
			# if stream not available, will leave 0 byte file almost immediately
			chk_pid=$(ps -U ${run_user} ux | awk '{print $2}' | grep -i ${run_pid})
			if [[ "${chk_pid}" == "" ]] ; then
				if [[ ${debug} -eq 1 ]] ; then msg_debug "Left 0 byte file quickly" ; fi
				tidy_files
				let server_num++
				if [[ ${server_num} -gt ${stream_server_len} ]] ; then
					if [[ ${debug} -eq 1 ]] ; then msg_debug "Failed to connect to all defined servers" ; fi
					server_num=0
					recordingokay=0
					sleep ${timer_medium}s 2>/dev/null
					break 2
				else
					recordingokay=0
					# sleep 10s 2>/dev/null
					continue
				fi
			fi
			sleep ${timer_medium}s 2>/dev/null
			# if got here somehow and still have a non-zero file, need to break loop as something is recording
			if [[ -s "${filesave}" ]] ; then
				if [[ ${debug} -eq 1 ]] ; then msg_debug "Failed through (success) as not zero byte file" ; fi
				# server_num=0
				let part++
				recordingokay=1
				break
			fi
			# if got here, then kill whatever might be running and exit
			end_pid ${run_pid}
			tidy_files
			let server_num++
			if [[ -s "${filesave}" ]] ; then
				let part++
			fi
			if [[ ${server_num} -gt ${stream_server_len} ]] ; then
				if [[ ${debug} -eq 1 ]] ; then msg_debug "Failed to connect to all defined servers" ; fi
				server_num=0
				recordingokay=0
				sleep ${timer_medium}s 2>/dev/null
				break 2
			fi
		done
	
		while true
		do	
			check_time=$(( end_time - $(date +%s) ))
			if [[ ${check_time} -le 5 ]] ; then 
				end_pid ${run_pid}
				tidy_files
				if [[ ${debug} -eq 1 ]] ; then msg_debug "Timer met - exit recording" ; fi
				exit 0
			fi
			let chkloop++
			chk_pid=$(ps -U ${run_user} ux | awk '{print $2}' | grep -i ${run_pid})
			if [[ "${chk_pid}" == "" ]] ; then
				tidy_files
				server_num=0
				recordingokay=0
				chkloop=0
				if [[ ${debug} -eq 1 ]] ; then msg_debug "Process ${run_pid} is no longer running" ; fi
				break 2
			fi
			if [[ ${chkloop} -gt 6 ]] && [[ ! -s "${filesave}" ]] ; then
				end_pid ${run_pid}
				tidy_files
				server_num=0
				recordingokay=0
				chkloop=0
				if [[ ${debug} -eq 1 ]] ; then msg_debug "Check Loop exceeded" ; fi
				break 2
			fi
			chk_filesize_1=$(stat -c %s "${filesave}")
			sleep ${timer_long}s 2>/dev/null
			chk_filesize_2=$(stat -c %s "${filesave}")
			if [[ ${chk_filesize_1} -eq ${chk_filesize_2} ]] ; then
				end_pid ${run_pid}
				tidy_files
				server_num=0
				recordingokay=0
				chkloop=0
				if [[ ${debug} -eq 1 ]] ; then msg_debug "File size not increasing" ; fi
				break 2
			fi
			sleep ${timer_medium}s 2>/dev/null
		done
	done
done
exit 0
