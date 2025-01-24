import urllib.parse
import zstandard as zstd
import gzip
import zlib
import json
import tls_client
import requests
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import tls_client
import requests
import urllib.parse
import zstandard as zstd
import gzip
import zlib
import json
import random 
import hmac
import base64
import time
from typing import Optional
import uuid



class CryptoPub:
    @staticmethod
    def encrypt_native(version: int, public_key_pem: str, data: str, nonce: str) -> bytes:
        
        try:
            # Load the public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Combine the data (similar to the original function)
            combined_data = f"{version}{data}{nonce}".encode('utf-8')
            
            # Encrypt the data
            encrypted_data = public_key.encrypt(
                combined_data,
                padding.PKCS1v15()
            )
            
            return encrypted_data
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise


#accountUid , deviceUid , max_id=0 , session_paging_token="" , session_id="" , paging_token=""
def login(username , actual_password):
    try:
        dataDict = json.loads(open(f"{username}.txt" , "r").read())
    except:
        deviceUid = str(uuid.uuid4())
        t = str(time.time()*1000)
        pwd = CryptoPub.encrypt_native(41, '''
                                    -----BEGIN PUBLIC KEY-----
                                    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcu1KMDR1vzuBr9iYKW8
                                    KWmhT8CVUBRkchiO8861H7zIOYRwkQrkeHA+0mkBo3Ly1PiLXDkbKQZyeqZbspke
                                    4e7WgFNwT23jHfRMV/cNPxjPEy4kxNEbzLET6GlWepGdXFhzHfnS1PinGQzj0ZOU
                                    ZM3pQjgGRL9fAf8brt1ewhQ5XtpvKFdPyQq5BkeFEDKoInDsC/yKDWRAx2twgPFr
                                    CYUzAB8/yXuL30ErTHT79bt3yTnv1fRtE19tROIlBuqruwSBk9gGq/LuvSECgsl5
                                    z4VcpHXhgZt6MhrAj6y9vAAxO2RVrt0Mq4OY4HgyYz9Wlr1vAxXXGAAYIvrhAYLP
                                    7QIDAQAB
                                    -----END PUBLIC KEY-----
                                    ''', actual_password, t)
        session = tls_client.Session(client_identifier="okhttp4_android_12",
                                    header_order=["x-ig-app-locale",
                                                "x-ig-device-locale",
                                                "x-ig-mapped-locale",
                                                "x-pigeon-session-id",
                                                "x-pigeon-rawclienttime",
                                                "x-ig-bandwidth-speed-kbps",
                                                "x-ig-bandwidth-totalbytes-b",
                                                "x-ig-bandwidth-totaltime-ms",
                                                "x-bloks-version-id",
                                                "x-ig-www-claim",
                                                "x-bloks-is-prism-enabled",
                                                "x-bloks-is-layout-rtl",
                                                "x-ig-device-id",
                                                "x-ig-family-device-id",
                                                "x-ig-android-id",
                                                "x-ig-timezone-offset",
                                                "x-fb-connection-type",
                                                "x-ig-connection-type",
                                                "x-ig-capabilities",
                                                "x-ig-app-id",
                                                "priority",
                                                "x-tigon-is-retry",
                                                "x-tigon-is-retry",
                                                "user-agent",
                                                "accept-language",
                                                "x-mid",
                                                "ig-intended-user-id",
                                                "content-type",
                                                "content-length",
                                                "accept-encoding",
                                                "x-fb-http-engine",
                                                "x-fb-client-ip",
                                                "x-fb-server-cluster"] , random_tls_extension_order=True)
        url = "https://i.instagram.com/api/v1/bloks/apps/com.bloks.www.bloks.caa.login.async.send_login_request/"
        headers = {
            "x-ig-app-locale": "en_US",
            "x-ig-device-locale": "en_US",
            "x-ig-mapped-locale": "en_US",
            "x-pigeon-session-id": f"UFS-{deviceUid}",
            "x-pigeon-rawclienttime": t,
            "x-ig-bandwidth-speed-kbps": "-1.000",
            "x-ig-bandwidth-totalbytes-b": "0",
            "x-ig-bandwidth-totaltime-ms": "0",
            "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
            "x-ig-www-claim": "0",
            "x-bloks-is-prism-enabled": "false",
            "x-bloks-is-layout-rtl": "false",
            "x-ig-device-id": deviceUid,
            "x-ig-family-device-id": deviceUid,
            "x-ig-android-id": f"android-{deviceUid}",
            "x-ig-timezone-offset": "3600",
            "x-fb-connection-type": "WIFI",
            "x-ig-connection-type": "WIFI",
            "x-ig-capabilities": "3brTv10=",
            "x-ig-app-id": "567067343352427",
            "priority": "u=3",
            "x-tigon-is-retry": "True",
            "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
            "accept-language": "en-US",
            "x-mid": "ZyKgYQABAAFqsfn15Aaog8g8ruZK",
            "ig-intended-user-id": "0",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept-encoding": "zstd, gzip, deflate",
            "x-fb-http-engine": "Liger",
            "x-fb-client-ip": "True",
            "x-fb-server-cluster": "True"
        }

        data ='params=%7B%22client_input_params%22%3A%7B%22sim_phones%22%3A%5B%5D%2C%22secure_family_device_id%22%3A%22%22%2C%22has_granted_read_contacts_permissions%22%3A0%2C%22auth_secure_device_id%22%3A%22%22%2C%22has_whatsapp_installed%22%3A1%2C%22password%22%3A%22%23PWD_INSTAGRAM%3A1%3A1730486806%3AASkrlgLlrGN1E3AiGmgAAQUEIEDTyptE3v%2BUmrIGr91B69b6sBuDSBE6XSH7%2BGH10qtqnLqUasC7sslLVxSjXLQm2LXus3hdis2hAIS8mfXm%2FxnsE9%2Fr8Te8Q4ZLO6dnOErPzyDtx8xScuiS6cy94ZRPhe6rK5WRaBbh0q%2FXxNhyZFMag8aK8jscA2YXM2al%2BKnqmuuxoo9oM74NGeOOfq%2BOP9HnYEKVAse%2FDeRi6Qk81dcT6COSjE9hlBVuIZgwDi7Qa3O1L%2FpWxUs%2F2Ck%2Fdv7cR%2FKLn%2BDLIV2QmWnzZStV411537JJOqe065QxQ4iR4tziZhcYu3Yotwyo1G%2BIhn7Y5mw%2BTGPXCgkGMD7quJeX4hkjpM4MVITPxLxPdjtHe0WZOuF8%2BiQ%3D%22%2C%22sso_token_map_json_string%22%3A%22%22%2C%22event_flow%22%3A%22login_manual%22%2C%22password_contains_non_ascii%22%3A%22false%22%2C%22client_known_key_hash%22%3A%22%22%2C%22encrypted_msisdn%22%3A%22%22%2C%22has_granted_read_phone_permissions%22%3A0%2C%22device_id%22%3A%22android-69c742fc0b549ac3%22%2C%22login_attempt_count%22%3A1%2C%22machine_id%22%3A%22ZyUh_gABAAG5XVHoFI86fbG89Zio%22%2C%22accounts_list%22%3A%5B%5D%2C%22family_device_id%22%3A%225db46ffe-fc52-41c8-aba1-ffddbff5d644%22%2C%22fb_ig_device_id%22%3A%5B%5D%2C%22device_emails%22%3A%5B%5D%2C%22try_num%22%3A1%2C%22lois_settings%22%3A%7B%22lois_token%22%3A%22%22%2C%22lara_override%22%3A%22%22%7D%2C%22event_step%22%3A%22home_page%22%2C%22headers_infra_flow_id%22%3A%22%22%2C%22openid_tokens%22%3A%7B%7D%2C%22contact_point%22%3A%22better_life_way77%22%7D%2C%22server_params%22%3A%7B%22should_trigger_override_login_2fa_action%22%3A0%2C%22is_from_logged_out%22%3A0%2C%22should_trigger_override_login_success_action%22%3A0%2C%22login_credential_type%22%3A%22none%22%2C%22server_login_source%22%3A%22login%22%2C%22waterfall_id%22%3Anull%2C%22login_source%22%3A%22Login%22%2C%22is_platform_login%22%3A0%2C%22INTERNAL__latency_qpl_marker_id%22%3A36707139%2C%22offline_experiment_group%22%3Anull%2C%22is_from_landing_page%22%3A0%2C%22password_text_input_id%22%3A%2235f7zg%3A68%22%2C%22is_from_empty_password%22%3A0%2C%22ar_event_source%22%3A%22login_home_page%22%2C%22username_text_input_id%22%3A%2235f7zg%3A67%22%2C%22layered_homepage_experiment_group%22%3Anull%2C%22should_show_nested_nta_from_aymh%22%3A1%2C%22device_id%22%3Anull%2C%22INTERNAL__latency_qpl_instance_id%22%3A1.9050679600182E13%2C%22reg_flow_source%22%3A%22login_home_native_integration_point%22%2C%22is_caa_perf_enabled%22%3A1%2C%22credential_type%22%3A%22password%22%2C%22is_from_password_entry_page%22%3A0%2C%22caller%22%3A%22gslr%22%2C%22family_device_id%22%3Anull%2C%22INTERNAL_INFRA_THEME%22%3A%22harm_f%22%2C%22is_from_assistive_id%22%3A0%2C%22access_flow_version%22%3A%22LEGACY_FLOW%22%2C%22is_from_logged_in_switcher%22%3A0%7D%7D&bk_client_context=%7B%22bloks_version%22%3A%229fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a%22%2C%22styles_id%22%3A%22instagram%22%7D&bloks_versioning_id=9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a'
        data = urllib.parse.parse_qs(data)
        data['params'][0] = json.loads((data['params'][0]))
        data['params'][0]["password"] = f"#PWD_INSTAGRAM:1:{t}:{pwd}"
        data['params'][0]["contact_point"]  = username
        data['params'][0] = json.dumps(data['params'][0])
        response = requests.post(url, headers=headers, data=data)
        content = response.content
        encoding = response.headers.get('Content-Encoding', '')
        try:
            if 'zstd' in encoding:
                dctx = zstd.ZstdDecompressor()
                content = dctx.decompress(content)
            elif 'gzip' in encoding:
                content = gzip.decompress(content)
            elif 'deflate' in encoding:
                content = zlib.decompress(content)
        except (zstd.ZstdError, OSError, zlib.error) as e:
            print(f"Failed to decompress content: {e}")
        try:
            content = content.decode(response.encoding or 'utf-8')
        except UnicodeDecodeError:
            print("Failed to decode content as UTF-8.")
        try:
            try :
                dt = content.split('"uuid": "')[1].split('"')[0]
            except:
                print(f"content Error {content}")
                exit(0)
            data = content.replace("\\" , "")
            accountId = data.split('{"pk":')[1].split('"')[0]
            dataDict = {"IG-Set-Authorization" :data.split('IG-Set-Authorization": "')[1].split('", "IG-Set-Password-Encryption-Key-Id')[0]
                        ,"uuid": f"{dt[0:7]}-{dt[8:11]}-{dt[12:15]}-{dt[16:]}",
                        "accountId":accountId , "deviceUid":deviceUid,"username":username , "password":actual_password}
            open(f"{username}.txt","w").write(json.dumps(dataDict))
            open('atext.txt' , "w" , encoding="utf-8").write(str(content))
            return dataDict
        except json.JSONDecodeError:
            print("Content is not JSON. Raw data:")
    
    if(not testExplore(dataDict.get("IG-Set-Authorization") ,dataDict.get("accountId") , dataDict.get("deviceUid"))):
        deviceUid = str(uuid.uuid4())
        t = str(time.time()*1000)
        pwd = CryptoPub.encrypt_native(41, '''
                                    -----BEGIN PUBLIC KEY-----
                                    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcu1KMDR1vzuBr9iYKW8
                                    KWmhT8CVUBRkchiO8861H7zIOYRwkQrkeHA+0mkBo3Ly1PiLXDkbKQZyeqZbspke
                                    4e7WgFNwT23jHfRMV/cNPxjPEy4kxNEbzLET6GlWepGdXFhzHfnS1PinGQzj0ZOU
                                    ZM3pQjgGRL9fAf8brt1ewhQ5XtpvKFdPyQq5BkeFEDKoInDsC/yKDWRAx2twgPFr
                                    CYUzAB8/yXuL30ErTHT79bt3yTnv1fRtE19tROIlBuqruwSBk9gGq/LuvSECgsl5
                                    z4VcpHXhgZt6MhrAj6y9vAAxO2RVrt0Mq4OY4HgyYz9Wlr1vAxXXGAAYIvrhAYLP
                                    7QIDAQAB
                                    -----END PUBLIC KEY-----
                                    ''', actual_password, t)
        session = tls_client.Session(client_identifier="okhttp4_android_12",
                                    header_order=["x-ig-app-locale",
                                                "x-ig-device-locale",
                                                "x-ig-mapped-locale",
                                                "x-pigeon-session-id",
                                                "x-pigeon-rawclienttime",
                                                "x-ig-bandwidth-speed-kbps",
                                                "x-ig-bandwidth-totalbytes-b",
                                                "x-ig-bandwidth-totaltime-ms",
                                                "x-bloks-version-id",
                                                "x-ig-www-claim",
                                                "x-bloks-is-prism-enabled",
                                                "x-bloks-is-layout-rtl",
                                                "x-ig-device-id",
                                                "x-ig-family-device-id",
                                                "x-ig-android-id",
                                                "x-ig-timezone-offset",
                                                "x-fb-connection-type",
                                                "x-ig-connection-type",
                                                "x-ig-capabilities",
                                                "x-ig-app-id",
                                                "priority",
                                                "x-tigon-is-retry",
                                                "x-tigon-is-retry",
                                                "user-agent",
                                                "accept-language",
                                                "x-mid",
                                                "ig-intended-user-id",
                                                "content-type",
                                                "content-length",
                                                "accept-encoding",
                                                "x-fb-http-engine",
                                                "x-fb-client-ip",
                                                "x-fb-server-cluster"] , random_tls_extension_order=True)
        url = "https://i.instagram.com/api/v1/bloks/apps/com.bloks.www.bloks.caa.login.async.send_login_request/"
        headers = {
            "x-ig-app-locale": "en_US",
            "x-ig-device-locale": "en_US",
            "x-ig-mapped-locale": "en_US",
            "x-pigeon-session-id": f"UFS-{deviceUid}",
            "x-pigeon-rawclienttime": t,
            "x-ig-bandwidth-speed-kbps": "-1.000",
            "x-ig-bandwidth-totalbytes-b": "0",
            "x-ig-bandwidth-totaltime-ms": "0",
            "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
            "x-ig-www-claim": "0",
            "x-bloks-is-prism-enabled": "false",
            "x-bloks-is-layout-rtl": "false",
            "x-ig-device-id": deviceUid,
            "x-ig-family-device-id": deviceUid,
            "x-ig-android-id": f"android-{deviceUid}",
            "x-ig-timezone-offset": "3600",
            "x-fb-connection-type": "WIFI",
            "x-ig-connection-type": "WIFI",
            "x-ig-capabilities": "3brTv10=",
            "x-ig-app-id": "567067343352427",
            "priority": "u=3",
            "x-tigon-is-retry": "True",
            "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
            "accept-language": "en-US",
            "x-mid": "ZyKgYQABAAFqsfn15Aaog8g8ruZK",
            "ig-intended-user-id": "0",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept-encoding": "zstd, gzip, deflate",
            "x-fb-http-engine": "Liger",
            "x-fb-client-ip": "True",
            "x-fb-server-cluster": "True"
        }

        data ='params=%7B%22client_input_params%22%3A%7B%22sim_phones%22%3A%5B%5D%2C%22secure_family_device_id%22%3A%22%22%2C%22has_granted_read_contacts_permissions%22%3A0%2C%22auth_secure_device_id%22%3A%22%22%2C%22has_whatsapp_installed%22%3A1%2C%22password%22%3A%22%23PWD_INSTAGRAM%3A1%3A1730486806%3AASkrlgLlrGN1E3AiGmgAAQUEIEDTyptE3v%2BUmrIGr91B69b6sBuDSBE6XSH7%2BGH10qtqnLqUasC7sslLVxSjXLQm2LXus3hdis2hAIS8mfXm%2FxnsE9%2Fr8Te8Q4ZLO6dnOErPzyDtx8xScuiS6cy94ZRPhe6rK5WRaBbh0q%2FXxNhyZFMag8aK8jscA2YXM2al%2BKnqmuuxoo9oM74NGeOOfq%2BOP9HnYEKVAse%2FDeRi6Qk81dcT6COSjE9hlBVuIZgwDi7Qa3O1L%2FpWxUs%2F2Ck%2Fdv7cR%2FKLn%2BDLIV2QmWnzZStV411537JJOqe065QxQ4iR4tziZhcYu3Yotwyo1G%2BIhn7Y5mw%2BTGPXCgkGMD7quJeX4hkjpM4MVITPxLxPdjtHe0WZOuF8%2BiQ%3D%22%2C%22sso_token_map_json_string%22%3A%22%22%2C%22event_flow%22%3A%22login_manual%22%2C%22password_contains_non_ascii%22%3A%22false%22%2C%22client_known_key_hash%22%3A%22%22%2C%22encrypted_msisdn%22%3A%22%22%2C%22has_granted_read_phone_permissions%22%3A0%2C%22device_id%22%3A%22android-69c742fc0b549ac3%22%2C%22login_attempt_count%22%3A1%2C%22machine_id%22%3A%22ZyUh_gABAAG5XVHoFI86fbG89Zio%22%2C%22accounts_list%22%3A%5B%5D%2C%22family_device_id%22%3A%225db46ffe-fc52-41c8-aba1-ffddbff5d644%22%2C%22fb_ig_device_id%22%3A%5B%5D%2C%22device_emails%22%3A%5B%5D%2C%22try_num%22%3A1%2C%22lois_settings%22%3A%7B%22lois_token%22%3A%22%22%2C%22lara_override%22%3A%22%22%7D%2C%22event_step%22%3A%22home_page%22%2C%22headers_infra_flow_id%22%3A%22%22%2C%22openid_tokens%22%3A%7B%7D%2C%22contact_point%22%3A%22better_life_way77%22%7D%2C%22server_params%22%3A%7B%22should_trigger_override_login_2fa_action%22%3A0%2C%22is_from_logged_out%22%3A0%2C%22should_trigger_override_login_success_action%22%3A0%2C%22login_credential_type%22%3A%22none%22%2C%22server_login_source%22%3A%22login%22%2C%22waterfall_id%22%3Anull%2C%22login_source%22%3A%22Login%22%2C%22is_platform_login%22%3A0%2C%22INTERNAL__latency_qpl_marker_id%22%3A36707139%2C%22offline_experiment_group%22%3Anull%2C%22is_from_landing_page%22%3A0%2C%22password_text_input_id%22%3A%2235f7zg%3A68%22%2C%22is_from_empty_password%22%3A0%2C%22ar_event_source%22%3A%22login_home_page%22%2C%22username_text_input_id%22%3A%2235f7zg%3A67%22%2C%22layered_homepage_experiment_group%22%3Anull%2C%22should_show_nested_nta_from_aymh%22%3A1%2C%22device_id%22%3Anull%2C%22INTERNAL__latency_qpl_instance_id%22%3A1.9050679600182E13%2C%22reg_flow_source%22%3A%22login_home_native_integration_point%22%2C%22is_caa_perf_enabled%22%3A1%2C%22credential_type%22%3A%22password%22%2C%22is_from_password_entry_page%22%3A0%2C%22caller%22%3A%22gslr%22%2C%22family_device_id%22%3Anull%2C%22INTERNAL_INFRA_THEME%22%3A%22harm_f%22%2C%22is_from_assistive_id%22%3A0%2C%22access_flow_version%22%3A%22LEGACY_FLOW%22%2C%22is_from_logged_in_switcher%22%3A0%7D%7D&bk_client_context=%7B%22bloks_version%22%3A%229fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a%22%2C%22styles_id%22%3A%22instagram%22%7D&bloks_versioning_id=9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a'
        data = urllib.parse.parse_qs(data)
        data['params'][0] = json.loads((data['params'][0]))
        data['params'][0]["password"] = f"#PWD_INSTAGRAM:1:{t}:{pwd}"
        data['params'][0]["contact_point"]  = username
        data['params'][0] = json.dumps(data['params'][0])
        
        response = requests.post(url, headers=headers, data=data)
        content = response.content
        encoding = response.headers.get('Content-Encoding', '')
        try:
            if 'zstd' in encoding:
                dctx = zstd.ZstdDecompressor()
                content = dctx.decompress(content)
            elif 'gzip' in encoding:
                content = gzip.decompress(content)
            elif 'deflate' in encoding:
                content = zlib.decompress(content)
        except (zstd.ZstdError, OSError, zlib.error) as e:
            print(f"Failed to decompress content: {e}")
        try:
            content = content.decode(response.encoding or 'utf-8')
        except UnicodeDecodeError:
            print("Failed to decode content as UTF-8.")
        try:
            open('atext.txt' , "w" , encoding="utf-8").write(str(data))
            data = content.replace("\\" , "")
            dt = data.split('"uuid": "')[1].split('"')[0]
            accountId = data.split('{"pk":')[1].split('"')[0]
            dataDict = {"IG-Set-Authorization" :data.split('IG-Set-Authorization": "')[1].split('", "IG-Set-Password-Encryption-Key-Id')[0]
                        #0b256c56-0663-4ceb-8adb-821c7ba2b9f5 , e563f42a-7-41b6-11-4343-15-b31ef2271e8500a4
                        ,"uuid": f"{dt[0:7]}-{dt[8:11]}-{dt[12:15]}-{dt[16:]}",
                        "accountId":accountId , "deviceUid":deviceUid,"username":username , "password":actual_password}
            open(f"{username}.txt","w").write(json.dumps(dataDict))
            open('atext.txt' , "w", encoding="utf-8").write(str(content))
            return dataDict
        except json.JSONDecodeError:
            print("Content is not JSON. Raw data:")
    else:
        return dataDict
def getComment():
    try:
        return random.choice(open("commentsDatabase.txt","r").readlines())
        
    except:
        print("Please Write comments you want to comment with under the file called commentsDatabase.txt , the delimiter is \\n")
        open("commentsDatabase.txt","w").write("") 
        time.sleep(10)
        exit(0)

getComment()
session = tls_client.Session(client_identifier="okhttp4_android_11")
def a0p(str1: str, str2: str) -> str:
  
    return str1 +'\n' +str2

class C204589Su:
    # Class variables (equivalent to Java static fields)
    A01 = b"iN4$aGr0m"
    A00 = A01  # This will be used as the key for HMAC
    
    @staticmethod
    def a00(i: int, i2: int, j: int) -> Optional[str]:
        
        try:
            # Create the message string (equivalent to StringBuilder operations)
            obj = f"{i} {j} {i2} {int(time.time() * 1000)}"
            
            # Create HMAC signature
            mac = hmac.new(
                key=C204589Su.A00,
                msg=obj.encode(),
                digestmod='sha256'
            )
            
            # Get the signature and encode it
            signature = base64.b64encode(mac.digest()).decode()
            
            # Encode the original message
            encoded_obj = base64.b64encode(obj.encode()).decode()
            
            # Concatenate the results using the A0P method
            return a0p(signature, encoded_obj)
            
        except Exception:
            return None

alphabet = 'abcdefghijklmnopqrstwxyz1234567890'

"""
def comment(authorization,mediaId,message ,accountUid , deviceUid ):
    url =f"https://i.instagram.com/api/v1/media/{mediaId}/comment/"
    headers = {
        "x-ig-app-locale": "en_US",
        "x-ig-device-locale": "en_US",
        "x-ig-mapped-locale": "en_US",
        "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
        "x-bloks-is-prism-enabled": "false",
        "x-bloks-is-layout-rtl": "false",
        "x-ig-device-id": deviceUid,
        "x-ig-family-device-id":deviceUid,
        "x-ig-android-id": "android-{deviceUid}",
        "x-ig-timezone-offset": "3600",
        "x-ig-nav-chain": f"MainFeedFragment:feed_timeline:1:cold_start:{time.time()-100}::,InteractivityBottomSheetFragment:feed_timeline:105:button:{time.time()-50}::,CommentThreadFragment:comments_v2:106:button:{time.time()-10}::",
        "x-fb-connection-type": "MOBILE.LTE",
        "x-ig-connection-type": "MOBILE(LTE)",
        "x-ig-capabilities": "3brTv10=",
        "x-ig-app-id": "567067343352427",
        "priority": "u=3",
        "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
        "accept-language": "en-US",
        "authorization": authorization,
        "x-mid": "ZyfOYQABAAEAfwYam8CdJAjb-QTw",
        "ig-u-ig-direct-region-hint": f"FRC,{accountUid},{deviceUid}:01f763acc37e7387fd50b863cc23b96f79284e20768c749aa5ddcd6fc434d690fe0288de",
        "ig-u-ds-user-id": accountUid,
        "ig-u-rur": f"LDC,{deviceUid},1762204597:{random.choices(alphabet , k=72)}",
        "ig-intended-user-id": accountUid,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept-encoding": "zstd, gzip, deflate",
        "x-fb-http-engine": "Liger",
        "x-fb-client-ip": "True",
        "x-fb-server-cluster": "True"
    }
    data = urllib.parse.parse_qs(data)
    SIGNATURE = json.loads(data["signed_body"][0].split("SIGNATURE.")[1])
    comment_creation_key = int(time.time()/10)
    #accountUid="_uid"
    #deviceUid = "_uuid"
    #message = "text"
    #accountUid="54586931999"
    #deviceUid = "fd1522f9-2663-4efd-89c8-435d6e988ddb"
    logging_info_token = ''.join(random.choices(alphabet , k=32))
    textlen = len(message)
    offsensiveScore = 0
    commentComposeDurationInTimeStamp = int((textlen/3.33)*1000)
    user_breadcrumb = C204589Su.a00(10, 0, 1285)
    idempotence_token = str(uuid.uuid4())
    SIGNATURE["user_breadcrumb"] = user_breadcrumb
    SIGNATURE["comment_creation_key"] = comment_creation_key
    SIGNATURE["_uuid"] = deviceUid
    SIGNATURE["_uid"] = accountUid
    SIGNATURE["logging_info_token"] = logging_info_token
    SIGNATURE["idempotence_token"] = idempotence_token
    SIGNATURE["comment_text"] = message
    signed_body = f"SIGNATURE.{json.dumps(SIGNATURE)}"

    data = {
    'signed_body': signed_body
}
    r = requests.post(url , headers=headers ,data=data)
    encoding = r.headers.get('Content-Encoding', '')
    content = r.content
    try:
        if 'zstd' in encoding:
            dctx = zstd.ZstdDecompressor()
            content = dctx.decompress(content)
        elif 'gzip' in encoding:
            content = gzip.decompress(content)
        elif 'deflate' in encoding:
            content = zlib.decompress(content)
    except (zstd.ZstdError, OSError, zlib.error) as e:
        print(f"Failed to decompress content: {e}")
    try:
        content = content.decode(r.encoding or 'utf-8')
    except UnicodeDecodeError:
        print("Failed to decode content as UTF-8.")
    try:
        data = json.loads(content)
        print(data)
        try:
            print(f'Name of account that commented :{data["comment"]["user"]["username"]}')
        except:
            pass
    except json.JSONDecodeError:
        print("Content is not JSON. Raw data:")
        print(content)
"""

def comment(authorization, mediaId, message, accountUid, deviceUid , _uuid):
    url = f"https://i.instagram.com/api/v1/media/{mediaId}/comment/"
    headers = {
        "x-ig-app-locale": "en_US",
        "x-ig-device-locale": "en_US",
        "x-ig-mapped-locale": "en_US",
        "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
        "x-bloks-is-prism-enabled": "false",
        "x-bloks-is-layout-rtl": "false",
        "x-ig-device-id": deviceUid,
        "x-ig-family-device-id": deviceUid,  # Adjusted for uniqueness
        "x-ig-android-id": f"android-{deviceUid.split('-')[0] if deviceUid.split('-')[0] else '69c742fc0b549ac3'}",
        "x-ig-timezone-offset": "3600",
        "x-fb-connection-type": "WIFI",
        "x-ig-connection-type": "WIFI",
        "x-ig-capabilities": "3brTv10=",
        "x-ig-app-id": "567067343352427",
        "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
        "authorization": authorization,
        "ig-u-ds-user-id": accountUid,
        "ig-intended-user-id": accountUid,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept-encoding": "gzip, deflate",
    }
    comment_creation_key = int(time.time())
    payload = {
   "include_media_code":"false",
   "user_breadcrumb":C204589Su.a00(len(message), 0, 0),
   "inventory_source":"recommended_explore_grid_cover_model",
   "starting_clips_media_id":"null",
   "comment_creation_key":"61865720",
   "delivery_class":"organic",
   "idempotence_token":str(uuid.uuid4()),
   "include_e2ee_mentioned_user_list":"false",
   "radio_type":"wifi-none",
   "_uid":accountUid,
   "_uuid":_uuid,
   "nav_chain":"ExploreFragment:explore_popular:5:main_search:1732190270.67::,DiscoveryChainingFeedFragment:feed_contextual_chain:6:button:1732190272.453::,InteractivityBottomSheetFragment:feed_contextual_chain:7:button:1732190274.383::,CommentThreadFragment:comments_v2:8:button:1732190274.460::",
   "logging_info_token":"AA==",
   "comment_text":message,
   "is_from_direct_channel":"false",
   "is_carousel_bumped_post":"false",
   "container_module":"comments_v2_feed_contextual_chain",
   "feed_position":"0"
}
    print(payload)
    # Signed body with simulated signature
    signed_body = f"SIGNATURE.{json.dumps(payload)}"
    data = {"signed_body": signed_body}

    try:
        # Sending POST request
        response = requests.post(url, headers=headers, data=data)
        content = response.content

        # Handle potential compression
        content = response.content
        encoding = response.headers.get('Content-Encoding', '')
        
        if 'zstd' in encoding:
                dctx = zstd.ZstdDecompressor()
                content = dctx.decompress(content)
        elif 'gzip' in encoding:
                content = gzip.decompress(content)
        elif 'deflate' in encoding:
                content = zlib.decompress(content)
        
        try:
            content = content.decode(response.encoding or 'utf-8')
            response_data = content
            print(content)
        except UnicodeDecodeError:
            print("Failed to decode content as UTF-8.")

        # Check for success or failure
        if response_data.get("status") == "ok" and "comment" in response_data:
            username = response_data["comment"]["user"].get("username", "Unknown")
            print(f"Comment successfully posted by: {username}")
        else:
            # Log detailed failure information
            print(f"Failed to post comment. Response: {response_data}")
            # Handle specific error messages
            if response_data.get("message"):
                print(f"Error Message: {response_data['message']}")
            else:
                print("No additional error information provided.")

    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response. Raw content: {content}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def find_ids_with_underscore(data):
    ids_with_underscore = []

    def recursive_search(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():  
                if key == "media" and isinstance(value, dict) :
                    ids_with_underscore.append(value.get("id"))
                recursive_search(value)  
        elif isinstance(obj, list):
            for item in obj:  
                recursive_search(item)

    recursive_search(data)
    return ids_with_underscore

def testExplore(authorization ,accountUid , deviceUid ):
    if(True):
        url =f"https://i.instagram.com/api/v1/discover/topical_explore/?is_prefetch=false&is_auto_refresh=false&phone_id={deviceUid}&is_ptr=false&module=explore_popular&reels_configuration=hide_hero&battery_level=20&is_nonpersonalized_explore=false&timezone_offset=3600&is_charging=1&is_dark_mode=1&will_sound_on=0&session_id={str(uuid.uuid4())}&paging_token={json.dumps({"total_num_items":0})}"
    headers = {
        "x-ig-app-locale": "en_US",
        "x-ig-device-locale": "en_US",
        "x-ig-mapped-locale": "en_US",
        "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
        "x-bloks-is-prism-enabled": "false",
        "x-bloks-is-layout-rtl": "false",
        "x-ig-device-id": deviceUid,
        "x-ig-family-device-id":deviceUid,
        "x-ig-android-id": "android-{deviceUid}",
        "x-ig-timezone-offset": "3600",
        "x-ig-nav-chain": f"MainFeedFragment:feed_timeline:1:cold_start:{time.time()-100}::,InteractivityBottomSheetFragment:feed_timeline:105:button:{time.time()-50}::,CommentThreadFragment:comments_v2:106:button:{time.time()-10}::",
        "x-fb-connection-type": "MOBILE.LTE",
        "x-ig-connection-type": "MOBILE(LTE)",
        "x-ig-capabilities": "3brTv10=",
        "x-ig-app-id": "567067343352427",
        "priority": "u=3",
        "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
        "accept-language": "en-US",
        "authorization": authorization,
        "x-mid": "ZyfOYQABAAEAfwYam8CdJAjb-QTw",
        "ig-u-ig-direct-region-hint": f"FRC,{accountUid},{deviceUid}:01f763acc37e7387fd50b863cc23b96f79284e20768c749aa5ddcd6fc434d690fe0288de",
        "ig-u-ds-user-id": accountUid,
        "ig-u-rur": f"LDC,{deviceUid},1762204597:{random.choices(alphabet , k=72)}",
        "ig-intended-user-id": accountUid,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept-encoding": "zstd, gzip, deflate",
        "x-fb-http-engine": "Liger",
        "x-fb-client-ip": "True",
        "x-fb-server-cluster": "True"
    }
    
    response = requests.get(url , headers=headers )
    content = response.content
    encoding = response.headers.get('Content-Encoding', '')
    try:
        if 'zstd' in encoding:
            dctx = zstd.ZstdDecompressor()
            content = dctx.decompress(content)
        elif 'gzip' in encoding:
            content = gzip.decompress(content)
        elif 'deflate' in encoding:
            content = zlib.decompress(content)
    except (zstd.ZstdError, OSError, zlib.error) as e:
        print(f"Failed to decompress content: {e}")
    try:
        content = content.decode(response.encoding or 'utf-8')
    except UnicodeDecodeError:
        print("Failed to decode content as UTF-8.")
    try:
        data = json.loads(content)
        ids = find_ids_with_underscore(data)
        for id in ids:
                print(ids)
                return True
        return False
        
    except json.JSONDecodeError:
        print("Content is not JSON. Raw data:")
        print(content)
    return False
def explore(authorization , accountUid , deviceUid , max_id=0 , session_paging_token="" , session_id="" , paging_token=""):
    max_id = max_id +1
    if(max_id==0 or session_paging_token=="" or session_id=="" or paging_token==""):
        url =f"https://i.instagram.com/api/v1/discover/topical_explore/?is_prefetch=false&is_auto_refresh=false&phone_id={deviceUid}&is_ptr=false&module=explore_popular&reels_configuration=hide_hero&battery_level=20&is_nonpersonalized_explore=false&timezone_offset=3600&is_charging=1&is_dark_mode=1&will_sound_on=0&session_id={str(uuid.uuid4())}&paging_token={json.dumps({"total_num_items":0})}"
    else:
        url =f"https://i.instagram.com/api/v1/discover/topical_explore/?is_prefetch=false&is_auto_refresh=false&phone_id={deviceUid}&is_ptr=false&module=explore_popular&reels_configuration=hide_hero&battery_level=20&is_nonpersonalized_explore=false&timezone_offset=3600&is_charging=1&is_dark_mode=1&will_sound_on=0&session_id={session_id}&paging_token={json.dumps({"total_num_items":0})}&session_paging_token={session_paging_token}&max_id={max_id}"
    headers = {
        "x-ig-app-locale": "en_US",
        "x-ig-device-locale": "en_US",
        "x-ig-mapped-locale": "en_US",
        "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
        "x-bloks-is-prism-enabled": "false",
        "x-bloks-is-layout-rtl": "false",
        "x-ig-device-id": deviceUid,
        "x-ig-family-device-id":deviceUid,
        "x-ig-android-id": "android-{deviceUid}",
        "x-ig-timezone-offset": "3600",
        "x-ig-nav-chain": f"MainFeedFragment:feed_timeline:1:cold_start:{time.time()-100}::,InteractivityBottomSheetFragment:feed_timeline:105:button:{time.time()-50}::,CommentThreadFragment:comments_v2:106:button:{time.time()-10}::",
        "x-fb-connection-type": "MOBILE.LTE",
        "x-ig-connection-type": "MOBILE(LTE)",
        "x-ig-capabilities": "3brTv10=",
        "x-ig-app-id": "567067343352427",
        "priority": "u=3",
        "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
        "accept-language": "en-US",
        "authorization": authorization,
        "x-mid": "ZyfOYQABAAEAfwYam8CdJAjb-QTw",
        "ig-u-ig-direct-region-hint": f"FRC,{accountUid},{deviceUid}:01f763acc37e7387fd50b863cc23b96f79284e20768c749aa5ddcd6fc434d690fe0288de",
        "ig-u-ds-user-id": accountUid,
        "ig-u-rur": f"LDC,{deviceUid},1762204597:{random.choices(alphabet , k=72)}",
        "ig-intended-user-id": accountUid,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept-encoding": "zstd, gzip, deflate",
        "x-fb-http-engine": "Liger",
        "x-fb-client-ip": "True",
        "x-fb-server-cluster": "True"
    }
    response = requests.get(url , headers=headers )
    content = response.content
    encoding = response.headers.get('Content-Encoding', '')
    try:
        if 'zstd' in encoding:
            dctx = zstd.ZstdDecompressor()
            content = dctx.decompress(content)
        elif 'gzip' in encoding:
            content = gzip.decompress(content)
        elif 'deflate' in encoding:
            content = zlib.decompress(content)
    except (zstd.ZstdError, OSError, zlib.error) as e:
        print(f"Failed to decompress content: {e}")
    try:
        content = content.decode(response.encoding or 'utf-8')
    except UnicodeDecodeError:
        print("Failed to decode content as UTF-8.")
    try:
        data = json.loads(content)
        open("file.json" , "w").write(json.dumps(data))
        session_paging_token = data["max_id"]
        session_id = data["rank_token"]
        paging_token = {"total_num_items":4,"last_non_organic_item":{"id":"0","index":3,"type":2}}
        ids = find_ids_with_underscore(data)
        for id in ids:
                sleepingTime =random.randint(10,120)
                cm = getComment()
                print(f"[+]Writing Comment: {cm} from AccountUid :{accountUid} at post {id}")
                comment(authorization , f"{id}",cm , accountUid ,deviceUid)
                print(f"sleeping {sleepingTime}s in AccountUid:{accountUid}")
                time.sleep(sleepingTime)
        print(f"search length ids : {len(ids)}")
        explore(accountUid , deviceUid , max_id , session_paging_token , session_id , paging_token)
    except json.JSONDecodeError:
        print("Content is not JSON. Raw data:")
        print(content)
    
def explorebySearch(uuid,authorization , accountUid , deviceUid ,searchTerm , page_index=0 , reels_max_id="" , next_max_id="" , rank_token=""  , page_token="" , paging_token={"total_num_items":4}):
    try:    
        if(page_index==0 or reels_max_id=="" or next_max_id=="" or rank_token==""):
            url =f"https://i.instagram.com/api/v1/fbsearch/top_serp/?search_surface=top_serp&timezone_offset=3600&count=100&query={searchTerm}"
        else:
            url = f"https://i.instagram.com/api/v1/fbsearch/top_serp/?search_surface=top_serp&reels_page_index={page_index}&timezone_offset=3600&has_more_reels=true&count=30&query={searchTerm}&reels_max_id={reels_max_id}&next_max_id={next_max_id}&rank_token={rank_token}&page_index={page_index}&page_token={page_token}&paging_token={json.dumps({"total_num_items":4})}"
        headers = {
        "x-ig-app-locale": "en_US",
        "x-ig-device-locale": "en_US",
        "x-ig-mapped-locale": "en_US",
        "x-bloks-version-id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
        "x-bloks-is-prism-enabled": "false",
        "x-bloks-is-layout-rtl": "false",
        "x-ig-device-id": deviceUid,
        "x-ig-family-device-id":deviceUid,
        "x-ig-android-id": "android-{deviceUid}",
        "x-ig-timezone-offset": "3600",
        "x-ig-nav-chain": f"MainFeedFragment:feed_timeline:1:cold_start:{time.time()-100}::,InteractivityBottomSheetFragment:feed_timeline:105:button:{time.time()-50}::,CommentThreadFragment:comments_v2:106:button:{time.time()-10}::",
        "x-fb-connection-type": "MOBILE.LTE",
        "x-ig-connection-type": "MOBILE(LTE)",
        "x-ig-capabilities": "3brTv10=",
        "x-ig-app-id": "567067343352427",
        "priority": "u=3",
        "user-agent": "Instagram 309.1.0.41.113 Android (33/13; 480dpi; 1080x2292; INFINIX/Infinix; Infinix X670; Infinix-X670; mt6781; en_US; 541635890)",
        "accept-language": "en-US",
        "authorization": authorization,
        "x-mid": "ZyfOYQABAAEAfwYam8CdJAjb-QTw",
        "ig-u-ig-direct-region-hint": f"FRC,{accountUid},{deviceUid}:01f763acc37e7387fd50b863cc23b96f79284e20768c749aa5ddcd6fc434d690fe0288de",
        "ig-u-ds-user-id": accountUid,
        "ig-u-rur": f"LDC,{deviceUid},1762204597:{random.choices(alphabet , k=72)}",
        "ig-intended-user-id": accountUid,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept-encoding": "zstd, gzip, deflate",
        "x-fb-http-engine": "Liger",
        "x-fb-client-ip": "True",
        "x-fb-server-cluster": "True"
    }
        response = requests.get(url , headers=headers )
        content = response.content
        encoding = response.headers.get('Content-Encoding', '')
        print(response.status_code)
        try:
            if 'zstd' in encoding:
                dctx = zstd.ZstdDecompressor()
                content = dctx.decompress(content)
            elif 'gzip' in encoding:
                content = gzip.decompress(content)
            elif 'deflate' in encoding:
                content = zlib.decompress(content)
        except (zstd.ZstdError, OSError, zlib.error) as e:
            print(f"Failed to decompress content: {e}")
        try:
            content = content.decode(response.encoding or 'utf-8')
        except UnicodeDecodeError:
            print("Failed to decode content as UTF-8.")
        try:
            data = json.loads(content)
            open("file.json" , "w").write(json.dumps(data))
            paging_token = {"total_num_items":4,"last_non_organic_item":{"id":"0","index":3,"type":2}}
            ids = find_ids_with_underscore(data)
            for id in ids:
                sleepingTime =random.randint(10,120)
                cm = getComment()
                print(f"[+]Writing Comment: {cm} from AccountUid :{accountUid} at post {id}")
                comment(authorization,f"{id}",cm , accountUid ,uuid)
                print(f"sleeping {sleepingTime}s in AccountUid:{accountUid}")
                time.sleep(sleepingTime)
            print(f"search length ids : {len(ids)}")
            reels_max_id = data.get("media_grid").get("reels_max_id")
            next_max_id = data.get("media_grid").get("next_max_id")
            rank_token = data.get("media_grid").get("rank_token")
            explorebySearch(accountUid , deviceUid ,searchTerm , page_index+1 , reels_max_id , next_max_id , rank_token , page_token , paging_token)
        except json.JSONDecodeError:
            print("Content is not JSON. Raw data:")
            print(content)
    except Exception as e :
        print(e)   
    
actual_password = "@@qrcode"
username = "better_life_way77"




lg = (login(username , actual_password))
print(lg)
#explorebySearch(,lg["IG-Set-Authorization"] , lg["accountId"] , lg["deviceUid"] ,"test")
#explorebySearch(lg["IG-Set-Authorization"] , lg["accountId"] , lg["deviceUid"] )
print(comment(lg["IG-Set-Authorization"],"3460681155839541797_60519778850","@elbahar.exe hello dear" , lg["accountId"] , lg["deviceUid"],lg["uuid"] ))
