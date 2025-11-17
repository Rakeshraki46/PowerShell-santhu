"""
Verizon SAML setup in Google Workspace

1) Admin SDK (service account + domain-wide delegation):
   - Ensure user
   - Ensure group
   - Ensure membership

2) Selenium UI automation:
   - From the 'Add custom SAML app' wizard page with 'App name' box visible,
     fill:
       - App name
       - ACS URL
       - Entity ID
       - Start URL
     and click through the wizard.

NOTE: This is NOT an official API. It automates the Admin console UI and may
break if Google changes the HTML.
"""

import os
import time
import traceback

from google.oauth2 import service_account
from googleapiclient.discovery import build

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

# ========= CONFIG =========

# Service account + admin
ADMIN_EMAIL = "rakesh.joruka@barathos.com"  # Workspace super admin
SERVICE_ACCOUNT_FILE = r"C:\Users\rakesh.joruka\Downloads\mydownloader-467806-aa8281bc6ac7.json"

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.group",
    "https://www.googleapis.com/auth/admin.directory.group.member",
]

# User to create/ensure
USER_EMAIL = "santoshyamsani13@barathos.com"
USER_FIRST_NAME = "Santosh"
USER_LAST_NAME = "Yamsani"
USER_PASSWORD = "P@ssword@1234"  # first login will require change

# Group to create/ensure
GROUP_EMAIL = "verizonpoc-group@barathos.com"
GROUP_NAME = "VerizonPOC_Group"
GROUP_DESCRIPTION = "Group for Verizon SAML POC"

# SAML app config (for Selenium)
APP_NAME = "VerizonPOC"
ACS_URLS = [
    "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer",
    "https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure_access/services/saml/login-consumer",
    "https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure_access/services/saml/login-consumer",
]
ENTITY_ID = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
START_URL = ACS_URLS[0]


# ========= ADMIN SDK PART (USERS / GROUPS) =========

def get_admin_service():
    if not os.path.isfile(SERVICE_ACCOUNT_FILE):
        raise FileNotFoundError(f"Service account JSON not found: {SERVICE_ACCOUNT_FILE}")

    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    delegated = creds.with_subject(ADMIN_EMAIL)
    service = build("admin", "directory_v1", credentials=delegated)
    return service


def ensure_user(service):
    """Create user if not exists, return user object."""
    try:
        user = service.users().get(userKey=USER_EMAIL).execute()
        print(f"[USER] Already exists: {USER_EMAIL}")
        return user
    except Exception:
        print(f"[USER] Creating user: {USER_EMAIL}")
        body = {
            "primaryEmail": USER_EMAIL,
            "name": {
                "givenName": USER_FIRST_NAME,
                "familyName": USER_LAST_NAME,
            },
            "password": USER_PASSWORD,
        }
        user = service.users().insert(body=body).execute()
        print(f"[USER] Created: {user['primaryEmail']}")
        return user


def ensure_group(service):
    """Create group if not exists, return group object."""
    groups = service.groups().list(domain=GROUP_EMAIL.split("@")[1]).execute()
    for g in groups.get("groups", []):
        if g["email"].lower() == GROUP_EMAIL.lower():
            print(f"[GROUP] Already exists: {GROUP_EMAIL}")
            return g

    print(f"[GROUP] Creating group: {GROUP_EMAIL}")
    body = {
        "email": GROUP_EMAIL,
        "name": GROUP_NAME,
        "description": GROUP_DESCRIPTION,
    }
    group = service.groups().insert(body=body).execute()
    print(f"[GROUP] Created: {group['email']}")
    return group


def ensure_membership(service, group, user):
    """Add user to group if not already a member."""
    try:
        service.members().get(groupKey=group["id"], memberKey=user["id"]).execute()
        print(f"[MEMBER] {USER_EMAIL} already in {GROUP_EMAIL}")
    except Exception:
        print(f"[MEMBER] Adding {USER_EMAIL} to {GROUP_EMAIL}")
        body = {
            "email": USER_EMAIL,
            "role": "MEMBER",
        }
        service.members().insert(groupKey=group["id"], body=body).execute()
        print("[MEMBER] Added successfully")


# ========= SELENIUM HELPERS =========

def find_in_any_frame(driver, base_timeout, by, locator, description):
    """
    Try to find an element first in default content, then inside each iframe.
    Returns the element or raises TimeoutException.
    """
    # Try top-level first
    driver.switch_to.default_content()
    wait = WebDriverWait(driver, base_timeout)
    try:
        elem = wait.until(EC.visibility_of_element_located((by, locator)))
        print(f"[SELENIUM] Found {description} in main page.")
        return elem
    except TimeoutException:
        print(f"[SELENIUM] {description} not in main page, scanning iframes...")

    # Try each iframe
    frames = driver.find_elements(By.TAG_NAME, "iframe")
    for idx, frame in enumerate(frames):
        try:
            driver.switch_to.default_content()
            driver.switch_to.frame(frame)
            wait = WebDriverWait(driver, base_timeout)
            elem = wait.until(EC.visibility_of_element_located((by, locator)))
            print(f"[SELENIUM] Found {description} in iframe index {idx}.")
            return elem
        except TimeoutException:
            continue

    driver.switch_to.default_content()
    raise TimeoutException(f"Could not find {description} in any frame using locator: {locator}")


# ========= SELENIUM PART (SAML APP CREATION) =========

def create_saml_app_via_selenium():
    print("\n[SELENIUM] Launching Chrome...")

    try:
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service)
        driver.maximize_window()
        base_wait = WebDriverWait(driver, 45)

        # 1. Open Admin Console and let you log in + navigate
        print("[SELENIUM] Opening https://admin.google.com/ ...")
        driver.get("https://admin.google.com/")

        print(
            "\n[SELENIUM] YOUR TURN IN CHROME:"
            "\n  1) Log in as admin (rakesh.joruka@barathos.com) and complete 2FA."
            "\n  2) In the Admin console, go to: Apps -> Web and mobile apps."
            "\n  3) Click: 'Add app' -> 'Add custom SAML app'."
            "\n  4) Stop when you see the first page with the 'App name' text box."
        )
        input("\n[SELENIUM] When the 'App name' field is visible, press ENTER here in PowerShell...")

        # ---- STEP 1: App details ----
        print("[SELENIUM] Looking for 'App name' input (any frame)...")
        app_name_locator = (
            "//input[@type='text' and ("
            "@name='appName' or "
            "contains(@aria-label,'App name') or "
            "contains(@aria-label,'Application name') or "
            "contains(@placeholder,'App name') or "
            "contains(@placeholder,'Application name')"
            ")]"
        )

        name_input = find_in_any_frame(
            driver,
            base_timeout=30,
            by=By.XPATH,
            locator=app_name_locator,
            description="App name field"
        )

        print("[SELENIUM] Filling app name...")
        name_input.clear()
        name_input.send_keys(APP_NAME)

        # Try to find the Continue button in the same frame
        driver.switch_to.default_content()
        cont_locator = "//span[contains(text(),'Continue')]/ancestor::button"
        cont_btn = find_in_any_frame(
            driver,
            base_timeout=30,
            by=By.XPATH,
            locator=cont_locator,
            description="'Continue' button (Step 1)"
        )
        print("[SELENIUM] Clicking 'Continue' (Step 1)...")
        cont_btn.click()

        # ---- STEP 2: Google IdP info ----
        print("[SELENIUM] Waiting for 'Continue' on IdP page (Step 2)...")
        cont2_btn = find_in_any_frame(
            driver,
            base_timeout=40,
            by=By.XPATH,
            locator=cont_locator,
            description="'Continue' button (Step 2)"
        )
        print("[SELENIUM] Clicking 'Continue' (Step 2)...")
        cont2_btn.click()

        # ---- STEP 3: Service provider details ----
        print("[SELENIUM] Looking for ACS / Entity ID / Start URL fields (Step 3)...")

        acs_locator = (
            "//input[@type='text' and ("
            "@name='acsUrl' or "
            "contains(@aria-label,'ACS') or "
            "contains(@aria-label,'ACS URL') or "
            "contains(@placeholder,'ACS URL')"
            ")]"
        )
        entity_locator = (
            "//input[@type='text' and ("
            "@name='entityId' or "
            "contains(@aria-label,'Entity ID') or "
            "contains(@placeholder,'Entity ID')"
            ")]"
        )
        start_locator = (
            "//input[@type='text' and ("
            "@name='startUrl' or "
            "contains(@aria-label,'Start URL') or "
            "contains(@placeholder,'Start URL')"
            ")]"
        )

        acs_input = find_in_any_frame(
            driver,
            base_timeout=40,
            by=By.XPATH,
            locator=acs_locator,
            description="ACS URL field"
        )
        print("[SELENIUM] Filling ACS URL...")
        acs_input.clear()
        acs_input.send_keys(ACS_URLS[0])

        entity_input = find_in_any_frame(
            driver,
            base_timeout=40,
            by=By.XPATH,
            locator=entity_locator,
            description="Entity ID field"
        )
        print("[SELENIUM] Filling Entity ID...")
        entity_input.clear()
        entity_input.send_keys(ENTITY_ID)

        start_input = find_in_any_frame(
            driver,
            base_timeout=40,
            by=By.XPATH,
            locator=start_locator,
            description="Start URL field"
        )
        print("[SELENIUM] Filling Start URL...")
        start_input.clear()
        start_input.send_keys(START_URL)

        # Continue to Step 4
        cont3_btn = find_in_any_frame(
            driver,
            base_timeout=40,
            by=By.XPATH,
            locator=cont_locator,
            description="'Continue' button (Step 3)"
        )
        print("[SELENIUM] Clicking 'Continue' (Step 3)...")
        cont3_btn.click()

        # ---- STEP 4: Attribute mapping (Finish) ----
        print("[SELENIUM] Waiting for 'Finish' button (Step 4)...")
        finish_locator = "//span[contains(text(),'Finish')]/ancestor::button"
        finish_btn = find_in_any_frame(
            driver,
            base_timeout=40,
            by=By.XPATH,
            locator=finish_locator,
            description="'Finish' button"
        )
        print("[SELENIUM] Clicking 'Finish'...")
        finish_btn.click()

        print(f"[SELENIUM] SAML app '{APP_NAME}' wizard completed. Verify it in Admin Console.")
        time.sleep(5)

    except Exception as e:
        print("\n[SELENIUM] ERROR while automating SAML app creation:")
        print(e)
        print("---- Traceback ----")
        traceback.print_exc()
        print("-------------------")
        input("[SELENIUM] Press ENTER to exit Selenium...")
    else:
        input("[SELENIUM] Press ENTER to close the browser...")
        driver.quit()


# ========= MAIN =========

def main():
    print("=" * 60)
    print("Verizon SAML setup in Google Workspace (Users/Groups + SAML UI)")
    print("=" * 60)

    # Part 1: Users & Groups via Admin SDK
    print("\n[1/3] Connecting to Admin SDK...")
    admin_service = get_admin_service()
    print("[OK] Admin SDK authenticated.")

    print("\n[2/3] Ensuring user / group / membership...")
    user = ensure_user(admin_service)
    group = ensure_group(admin_service)
    ensure_membership(admin_service, group, user)

    # Part 2: SAML app via Selenium
    print("\n[3/3] Creating Custom SAML app via Selenium...")
    create_saml_app_via_selenium()

    print("\nDone. Check Admin Console:")
    print(f"  - User:  {USER_EMAIL}")
    print(f"  - Group: {GROUP_EMAIL}")
    print(f"  - SAML App Name: {APP_NAME}")
    print("=" * 60)


if __name__ == "__main__":
    main()
