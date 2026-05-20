import re
from datetime import datetime
import json

# Standard helper to parse dates from various formats
def parse_time(time_str):
    if not time_str:
        return datetime.now()
    # Try standard ISO formats
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%H:%M:%S", "%I:%M %p"):
        try:
            return datetime.strptime(time_str.strip(), fmt)
        except ValueError:
            continue
    # If it's just a number, treat as timestamp
    try:
        return datetime.fromtimestamp(float(time_str))
    except (ValueError, TypeError):
        pass
    return datetime.now()

# Simple geodistance heuristic to check for impossible travel
# Returns True if distance between loc1 and loc2 is physically impossible in the time delta (in minutes)
def is_impossible_travel(loc1, loc2, minutes_diff):
    if not loc1 or not loc2 or loc1 == loc2:
        return False
    
    # Normalize
    l1 = loc1.lower().strip()
    l2 = loc2.lower().strip()
    
    # Define some mock distances (approximate in miles) between major global regions/cities
    # If they are different countries, assume high distance unless they are very close
    # For a robust heuristic: if different major cities and time difference is small
    if l1 != l2:
        # If time difference is less than 30 minutes, almost any different location is impossible
        if minutes_diff < 30:
            return True
        # If time difference is less than 360 minutes (6 hours) and they represent different countries
        # (e.g. London to New York, Tokyo to Paris), it's impossible travel
        countries_or_cities = ["new york", "london", "tokyo", "paris", "india", "usa", "germany", "china", "sydney"]
        major_diff = False
        for place in countries_or_cities:
            if (place in l1 and place not in l2) or (place in l2 and place not in l1):
                major_diff = True
        if major_diff and minutes_diff < 300: # Less than 5 hours for transatlantic/transpacific
            return True
            
    return False

class SecurityEngine:
    
    @staticmethod
    def classify_risk(ip, device, location, time, failed_attempts, previous_locations):
        # Normalize failed attempts
        try:
            failed_attempts = int(failed_attempts)
        except (ValueError, TypeError):
            failed_attempts = 0

        # Normalize previous locations list
        if isinstance(previous_locations, str):
            # Try to parse as JSON list, or split by comma
            try:
                prev_locs = json.loads(previous_locations)
                if not isinstance(prev_locs, list):
                    prev_locs = [x.strip() for x in previous_locations.split(",") if x.strip()]
            except json.JSONDecodeError:
                prev_locs = [x.strip() for x in previous_locations.split(",") if x.strip()]
        elif isinstance(previous_locations, list):
            prev_locs = previous_locations
        else:
            prev_locs = []

        prev_locs_lower = [loc.lower().strip() for loc in prev_locs]
        curr_loc_lower = location.lower().strip() if location else ""

        # Evaluate risk score
        risk_score = 0
        reasons = []

        if failed_attempts >= 5:
            risk_score += 60
            reasons.append(f"High number of failed attempts ({failed_attempts}) in the last 10 minutes")
        elif failed_attempts >= 2:
            risk_score += 30
            reasons.append(f"Multiple failed attempts ({failed_attempts}) detected")

        if curr_loc_lower and prev_locs_lower:
            if curr_loc_lower not in prev_locs_lower:
                risk_score += 30
                reasons.append(f"Login from an unrecognized location: '{location}' (known: {', '.join(prev_locs)})")
        elif curr_loc_lower and not prev_locs_lower:
            # First time location
            risk_score += 15
            reasons.append(f"First login from location '{location}'")

        # Let's check for generic suspicious device indicators (like 'Unknown Device', 'curl', 'Postman', 'Python-urllib')
        dev_lower = device.lower() if device else ""
        if "curl" in dev_lower or "python" in dev_lower or "postman" in dev_lower or "unknown" in dev_lower:
            risk_score += 20
            reasons.append(f"Suspicious client device fingerprint: '{device}'")

        # Determine risk level and recommendation
        if risk_score >= 60:
            risk_level = "High"
            recommendation = "Block"
        elif risk_score >= 30:
            risk_level = "Medium"
            recommendation = "Challenge with OTP"
        else:
            risk_level = "Low"
            recommendation = "Allow"

        if not reasons:
            reasons.append("Login details match normal user profile with no failed attempts.")

        return {
            "risk_level": risk_level,
            "reason": " | ".join(reasons[:2]),
            "recommendation": recommendation
        }

    @staticmethod
    def detect_suspicious_activity(logs):
        # logs can be a string or a list of dicts. Normalize to list of dicts.
        parsed_logs = []
        if isinstance(logs, str):
            # Try parsing as JSON
            try:
                data = json.loads(logs)
                if isinstance(data, list):
                    parsed_logs = data
            except json.JSONDecodeError:
                # Parse as text line-by-line
                # Look for patterns like: timestamp, ip, user, location, device, action/status
                lines = logs.strip().split("\n")
                for line in lines:
                    if not line.strip():
                        continue
                    # Try to extract elements via simple regex or splits
                    # Example format: "2026-05-20 22:10:00 - User: admin - IP: 192.168.1.10 - Location: New York - Device: Chrome - Action: Login Failed"
                    ip_match = re.search(r"IP:\s*([\d\.]+)", line, re.IGNORECASE)
                    user_match = re.search(r"User(?:name)?:\s*([^\s|-]+)", line, re.IGNORECASE)
                    loc_match = re.search(r"Loc(?:ation)?:\s*([^|-]+)", line, re.IGNORECASE)
                    dev_match = re.search(r"Dev(?:ice)?:\s*([^|-]+)", line, re.IGNORECASE)
                    action_match = re.search(r"Action|Status:\s*([^|-]+)", line, re.IGNORECASE)
                    time_match = re.match(r"^([\d\-:\s]+)", line)

                    parsed_logs.append({
                        "timestamp": time_match.group(1).strip() if time_match else "",
                        "ip": ip_match.group(1).strip() if ip_match else "Unknown",
                        "username": user_match.group(1).strip() if user_match else "Unknown",
                        "location": loc_match.group(1).strip() if loc_match else "Unknown",
                        "device": dev_match.group(1).strip() if dev_match else "Unknown",
                        "action": action_match.group(1).strip() if action_match else line
                    })
        elif isinstance(logs, list):
            parsed_logs = logs

        if not parsed_logs:
            return {
                "status": "Normal",
                "explanation": "No logs available or format is unrecognized.",
                "suggestion": "Keep monitoring authentication channels."
            }

        # Analyze logs
        suspicious_findings = []
        brute_force_detected = False
        device_switching_detected = False
        impossible_travel_detected = False
        session_hijacking_detected = False

        # Group attempts by user & IP
        user_attempts = {}
        ip_attempts = {}
        user_devices = {}
        user_locations = {}

        for log in parsed_logs:
            user = log.get("username", "Unknown")
            ip = log.get("ip", "Unknown")
            loc = log.get("location", "Unknown")
            dev = log.get("device", "Unknown")
            act = log.get("action", "").lower()
            ts_str = log.get("timestamp", "")
            ts = parse_time(ts_str)

            # 1. Track failed attempts for brute force
            is_failed = "fail" in act or "reject" in act or "deny" in act
            if user != "Unknown":
                user_attempts.setdefault(user, []).append((ts, is_failed, ip, loc, dev))
                user_devices.setdefault(user, set()).add(dev)
                user_locations.setdefault(user, []).append((ts, loc))
            if ip != "Unknown":
                ip_attempts.setdefault(ip, []).append((ts, is_failed, user))

        # Check brute force (3+ failures within short window)
        for user, attempts in user_attempts.items():
            failures = [a for a in attempts if a[1]]
            if len(failures) >= 3:
                # Check timeframe of failures
                failures.sort(key=lambda x: x[0])
                time_span = (failures[-1][0] - failures[0][0]).total_seconds()
                if time_span <= 600: # 10 mins
                    brute_force_detected = True
                    suspicious_findings.append(f"Brute force: User '{user}' has {len(failures)} failed attempts within {int(time_span)}s.")

        for ip, attempts in ip_attempts.items():
            failures = [a for a in attempts if a[1]]
            if len(failures) >= 5:
                brute_force_detected = True
                suspicious_findings.append(f"Brute force: IP '{ip}' has {len(failures)} failed attempts targeting multiple accounts.")

        # Check device switching (user logs in from 3+ different devices within short timeframe)
        for user, devices in user_devices.items():
            if len(devices) >= 3:
                device_switching_detected = True
                suspicious_findings.append(f"Unusual device switching: User '{user}' accessed system from {len(devices)} different devices: {list(devices)}.")

        # Check impossible travel
        for user, loc_history in user_locations.items():
            if len(loc_history) >= 2:
                # Sort by timestamp
                loc_history.sort(key=lambda x: x[0])
                for i in range(len(loc_history) - 1):
                    t1, l1 = loc_history[i]
                    t2, l2 = loc_history[i+1]
                    diff_mins = (t2 - t1).total_seconds() / 60.0
                    if is_impossible_travel(l1, l2, diff_mins):
                        impossible_travel_detected = True
                        suspicious_findings.append(
                            f"Impossible travel detected for user '{user}': logged in from '{l1}' and '{l2}' within {int(diff_mins)} minutes."
                        )

        # Check session hijacking (e.g. user changes IP or Device during successful actions)
        for user, attempts in user_attempts.items():
            successes = [a for a in attempts if not a[1]] # successful logins
            if len(successes) >= 2:
                successes.sort(key=lambda x: x[0])
                for i in range(len(successes) - 1):
                    t1, _, ip1, loc1, dev1 = successes[i]
                    t2, _, ip2, loc2, dev2 = successes[i+1]
                    # If device or IP changes instantly (e.g., within 2 minutes)
                    diff_sec = (t2 - t1).total_seconds()
                    if diff_sec < 120 and (ip1 != ip2 or dev1 != dev2):
                        session_hijacking_detected = True
                        suspicious_findings.append(
                            f"Potential Session Hijacking for user '{user}': IP changed from {ip1} to {ip2} or device from '{dev1}' to '{dev2}' within {int(diff_sec)}s."
                        )

        is_suspicious = "Suspicious" if suspicious_findings else "Normal"
        explanation = " | ".join(suspicious_findings) if suspicious_findings else "No anomalous activity or attack patterns detected in the logs."
        
        # Determine suggestion
        if session_hijacking_detected or impossible_travel_detected:
            suggestion = "Terminate all active sessions, initiate password reset, and enable mandatory multi-factor authentication."
        elif brute_force_detected:
            suggestion = "Implement temporary IP lockout/rate-limiting and prompt targeted accounts to solve security challenges or reset credentials."
        elif device_switching_detected:
            suggestion = "Challenge new device sessions with email/SMS verification and alert the user."
        else:
            suggestion = "None required. Maintain standard activity logging."

        return {
            "status": is_suspicious,
            "explanation": explanation,
            "suggestion": suggestion
        }

    @staticmethod
    def resolve_session_conflict(sessions):
        # Normalize sessions
        parsed_sessions = []
        if isinstance(sessions, str):
            try:
                data = json.loads(sessions)
                if isinstance(data, list):
                    parsed_sessions = data
            except json.JSONDecodeError:
                # Text parsing helper for lines
                lines = sessions.strip().split("\n")
                for idx, line in enumerate(lines):
                    if not line.strip():
                        continue
                    sid_match = re.search(r"Session(?:_ID)?:\s*([^\s|-]+)", line, re.IGNORECASE)
                    ip_match = re.search(r"IP:\s*([\d\.]+)", line, re.IGNORECASE)
                    loc_match = re.search(r"Loc(?:ation)?:\s*([^|-]+)", line, re.IGNORECASE)
                    dev_match = re.search(r"Dev(?:ice)?:\s*([^|-]+)", line, re.IGNORECASE)
                    time_match = re.search(r"Active|Time:\s*([^|-]+)", line, re.IGNORECASE)
                    
                    parsed_sessions.append({
                        "session_id": sid_match.group(1).strip() if sid_match else f"session_{idx+1}",
                        "ip": ip_match.group(1).strip() if ip_match else "Unknown",
                        "location": loc_match.group(1).strip() if loc_match else "Unknown",
                        "device": dev_match.group(1).strip() if dev_match else "Unknown",
                        "last_active": time_match.group(1).strip() if time_match else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
        elif isinstance(sessions, list):
            parsed_sessions = sessions

        if not parsed_sessions:
            return {
                "decision": "No active sessions",
                "reason": "No active session records were provided.",
                "actions": {}
            }

        if len(parsed_sessions) == 1:
            sid = parsed_sessions[0].get("session_id", "session_1")
            return {
                "decision": "Keep all sessions",
                "reason": "Only one active session exists for this user.",
                "actions": {sid: "Keep"}
            }

        # Check for geographical discrepancies (impossible travel among active sessions)
        locations = [s.get("location", "Unknown") for s in parsed_sessions]
        unique_locations = list(set([loc for loc in locations if loc != "Unknown"]))
        
        # Check active session conflicts
        impossible_travel = False
        if len(unique_locations) >= 2:
            # Let's see if we have timestamps to verify, or if they are concurrent
            # If active sessions exist in different places concurrently, we flag a critical conflict
            impossible_travel = True

        actions = {}
        # Sort sessions by last_active descending (most recent first)
        sessions_with_times = []
        for s in parsed_sessions:
            sid = s.get("session_id", "Unknown")
            ts = parse_time(s.get("last_active", ""))
            sessions_with_times.append((s, ts))
        
        sessions_with_times.sort(key=lambda x: x[1], reverse=True)

        if impossible_travel:
            decision = "Flag conflict"
            reason = f"Active concurrent sessions detected in physically disparate locations: {', '.join(unique_locations)}. High risk of session hijacking."
            # Terminate older sessions, suspend the most recent session for verification
            most_recent_sid = sessions_with_times[0][0].get("session_id")
            actions[most_recent_sid] = "Suspend for Verification"
            for s, _ in sessions_with_times[1:]:
                actions[s.get("session_id")] = "Terminate"
        else:
            # Sessions from same location but different devices or IPs
            # Rule: Keep the 2 most recent sessions, terminate older ones to prevent abuse/sharing
            decision = "Terminate older sessions"
            reason = "Multiple active sessions from the same location. Terminating older sessions to adhere to concurrent session limits (max 2) and optimize security."
            
            for idx, (s, _) in enumerate(sessions_with_times):
                sid = s.get("session_id")
                if idx < 2:
                    actions[sid] = "Keep"
                else:
                    actions[sid] = "Terminate"

        return {
            "decision": decision,
            "reason": reason,
            "actions": actions
        }

    @staticmethod
    def summarize_auth_logs(logs):
        # logs can be string or list
        parsed_logs = []
        if isinstance(logs, str):
            try:
                data = json.loads(logs)
                if isinstance(data, list):
                    parsed_logs = data
            except json.JSONDecodeError:
                # Text parsing
                lines = logs.strip().split("\n")
                for line in lines:
                    if not line.strip():
                        continue
                    ip_match = re.search(r"IP:\s*([\d\.]+)", line, re.IGNORECASE)
                    user_match = re.search(r"User(?:name)?:\s*([^\s|-]+)", line, re.IGNORECASE)
                    loc_match = re.search(r"Loc(?:ation)?:\s*([^|-]+)", line, re.IGNORECASE)
                    action_match = re.search(r"Action|Status:\s*([^|-]+)", line, re.IGNORECASE)
                    parsed_logs.append({
                        "ip": ip_match.group(1).strip() if ip_match else "Unknown",
                        "username": user_match.group(1).strip() if user_match else "Unknown",
                        "location": loc_match.group(1).strip() if loc_match else "Unknown",
                        "action": action_match.group(1).strip() if action_match else line
                    })
        elif isinstance(logs, list):
            parsed_logs = logs

        if not parsed_logs:
            return {
                "summary": "Empty log data. 0 activities recorded.",
                "suspicious_patterns": "None",
                "insights": "No insights available."
            }

        total_attempts = len(parsed_logs)
        successes = 0
        failures = 0
        ips = set()
        users = set()
        locations = set()
        suspicious_patterns_list = []

        user_failures = {}
        ip_failures = {}

        for log in parsed_logs:
            act = log.get("action", "").lower()
            ip = log.get("ip", "Unknown")
            usr = log.get("username", "Unknown")
            loc = log.get("location", "Unknown")

            ips.add(ip)
            users.add(usr)
            locations.add(loc)

            if "fail" in act or "reject" in act or "deny" in act:
                failures += 1
                if usr != "Unknown":
                    user_failures[usr] = user_failures.get(usr, 0) + 1
                if ip != "Unknown":
                    ip_failures[ip] = ip_failures.get(ip, 0) + 1
            elif "success" in act or "allow" in act or "accept" in act:
                successes += 1

        summary = (
            f"Analyzed {total_attempts} login events across {len(users)} users, {len(ips)} IPs, "
            f"and {len(locations)} locations. Results: {successes} successful logins and {failures} failed attempts."
        )

        # Highlight top failures
        for usr, count in user_failures.items():
            if count >= 3:
                suspicious_patterns_list.append(f"User '{usr}' targeted with {count} failed login attempts.")
        for ip, count in ip_failures.items():
            if count >= 4:
                suspicious_patterns_list.append(f"IP address '{ip}' generated {count} failed authentication requests.")

        # Heuristic for credential stuffing (one IP targeting multiple users)
        ip_targets = {}
        for log in parsed_logs:
            ip = log.get("ip")
            usr = log.get("username")
            act = log.get("action", "").lower()
            if ip and usr and ("fail" in act or "reject" in act):
                ip_targets.setdefault(ip, set()).add(usr)

        for ip, targeted_users in ip_targets.items():
            if len(targeted_users) >= 3:
                suspicious_patterns_list.append(
                    f"Credential Stuffing indicator: IP '{ip}' targeted {len(targeted_users)} unique usernames with failed logins."
                )

        suspicious_patterns = " | ".join(suspicious_patterns_list) if suspicious_patterns_list else "No prominent suspicious patterns detected."

        # Compile insights
        insights = []
        if failures > total_attempts * 0.5:
            insights.append("High overall failure rate (>50%). Inspect for ongoing credential scanning or brute force attacks.")
        if ip_failures:
            max_fail_ip = max(ip_failures, key=ip_failures.get)
            insights.append(f"Consider blocking or rate-limiting IP '{max_fail_ip}' which has the highest failure volume ({ip_failures[max_fail_ip]}).")
        if user_failures:
            max_fail_user = max(user_failures, key=user_failures.get)
            insights.append(f"User account '{max_fail_user}' is highly targeted. Suggest enforcing multi-factor authentication (MFA) and reviewing password strength.")
        
        if not insights:
            insights.append("Log traffic is normal. Continue regular audit reviews and maintain current access policies.")

        return {
            "summary": summary,
            "suspicious_patterns": suspicious_patterns,
            "insights": " ".join(insights)
        }

    @staticmethod
    def detect_brute_force(login_attempts):
        # Normalize login_attempts
        parsed_attempts = []
        if isinstance(login_attempts, str):
            try:
                data = json.loads(login_attempts)
                if isinstance(data, list):
                    parsed_attempts = data
            except json.JSONDecodeError:
                # Text parsing
                lines = login_attempts.strip().split("\n")
                for line in lines:
                    if not line.strip():
                        continue
                    ip_match = re.search(r"IP:\s*([\d\.]+)", line, re.IGNORECASE)
                    user_match = re.search(r"User(?:name)?:\s*([^\s|-]+)", line, re.IGNORECASE)
                    status_match = re.search(r"Status|Action:\s*([^|-]+)", line, re.IGNORECASE)
                    parsed_attempts.append({
                        "ip": ip_match.group(1).strip() if ip_match else "Unknown",
                        "username": user_match.group(1).strip() if user_match else "Unknown",
                        "status": status_match.group(1).strip() if status_match else line
                    })
        elif isinstance(login_attempts, list):
            parsed_attempts = login_attempts

        if not parsed_attempts:
            return {
                "attack_detected": "No",
                "confidence_level": "Low",
                "recommended_action": "None"
            }

        total = len(parsed_attempts)
        failures = 0
        ips = {}
        users = {}
        ip_users = {}

        for att in parsed_attempts:
            status = att.get("status", "").lower()
            ip = att.get("ip", "Unknown")
            usr = att.get("username", "Unknown")
            is_fail = "fail" in status or "reject" in status or "deny" in status

            if is_fail:
                failures += 1
                ips[ip] = ips.get(ip, 0) + 1
                users[usr] = users.get(usr, 0) + 1
                ip_users.setdefault(ip, set()).add(usr)

        attack_detected = "No"
        confidence = "Low"
        recommended_action = "None"

        # Check conditions
        max_ip_fails = max(ips.values()) if ips else 0
        max_user_fails = max(users.values()) if users else 0
        
        # Check credential stuffing (one IP targeting multiple users)
        credential_stuffing = False
        stuffing_ip = None
        for ip, targeted_users in ip_users.items():
            if len(targeted_users) >= 3 and ips.get(ip, 0) >= 4:
                credential_stuffing = True
                stuffing_ip = ip
                break

        if credential_stuffing:
            attack_detected = "Yes"
            confidence = "High"
            recommended_action = f"block IP ({stuffing_ip}) & rate limit access"
        elif max_ip_fails >= 5:
            attack_detected = "Yes"
            confidence = "High"
            # find IP
            target_ip = [ip for ip, count in ips.items() if count == max_ip_fails][0]
            recommended_action = f"block IP ({target_ip})"
        elif max_ip_fails >= 3 or max_user_fails >= 3:
            attack_detected = "Yes"
            confidence = "Medium"
            recommended_action = "rate limit"
        elif failures > 0:
            attack_detected = "No"
            confidence = "Low"
            recommended_action = "alert admin"

        return {
            "attack_detected": attack_detected,
            "confidence_level": confidence,
            "recommended_action": recommended_action
        }
