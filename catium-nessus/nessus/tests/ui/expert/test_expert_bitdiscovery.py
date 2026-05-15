"""
Test cases for BitDiscovery feature integrated in 10.3.0

:copyright: Tenable Network Security, 2022
:date: Jul 19, 2022
:last_modified: March 08, 2023
:author: @mdabra
"""
import pytest
from waiting import wait
from catium.lib.const import TIME_THIRTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.wait import wait
from nessus.lib.const.constants import Nessus, API
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.helpers.license import close_welcome_nessus_10_modal_for_pro
from nessus.pageobjects.login.login_page import LoginPage
from nessus.helpers.scan import scan_save_launch_and_status_verification
from nessus.pageobjects.scans.scan_view_page import ScansASDHostsList
from nessus.pageobjects.generic.generic_modals import FilterModal


log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestExpertBitDiscovery:
    """ Test cases for BitDiscovery feature available in the Nessus Expert"""
    cat = None

    @pytest.mark.xray(test_key='NES-16259')
    @pytest.mark.order(1)
    def test_attack_surface_discovery_template_availability(self):
        """
        NES-16259: - Verify the availability of Attack Surface Discovery template
        Steps:
        1. Install Nessus Expert
        2. Go to scan page and click on create new scan
        3. Check whether we have a template named Attack Surface Discovery in the scan.
        """
        login_page = LoginPage()
        login_page.refresh()
        login_page.login_with_defaults() if login_page.is_element_present(
            'username_field', timeout=TIME_THIRTY_SECONDS) else log.warning('User has been logged in already..!!')
        try:
            close_welcome_nessus_10_modal_for_pro()
        except:
            log.warning('The Welcome to Nessus 10 modal did not appear')
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
            "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")
        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present("bd_scanner_tab"), waiting_for="Scan page gets loaded properly")
        list_of_templates = scan_page.get_all_scan_templates(Nessus.Scan.ScanTemplateTabs.SCANNER_TAB.lower())
        assert 'Attack Surface Discovery' in list_of_templates, "Attack Surface Discovery template is NOT available"
        log.info('The attack surface discovery template is available in the list')

    @pytest.mark.xray(test_key='NES-16263')
    @pytest.mark.xray(test_key='NES-16260')
    @pytest.mark.order(2)
    @pytest.mark.nessus_smoke
    @pytest.mark.parametrize("create_scan_bit_discovery",
                             [{'template_name': Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY,
                               'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_attack_surface_discovery_verify_scan(self, create_scan_bit_discovery):
        """
        NES-16260: Verify the scan works fine using Attack Surface Discovery template
        NES-16263 Verify completed scan shows result in 3 tabs - Summary, Records, & History
        Steps:
        1. Create a scan config using the attack surface discovery template
        2. Launch the saved scan config
        3. Verify that the scan gets completed.
        4. Once completed check the tabs available in the result
        """
        created_scan = create_scan_bit_discovery
        result = scan_save_launch_and_status_verification(scan_name=created_scan,
                                                          scan_status=API.Scan.Status.COMPLETED,
                                                          scan_folder_name=Nessus.Scan.Folder.MY_SCANS)
        assert result, "The scan did not get complete"
        log.info("The attack surface scan gets completed.")
        log.info("Starting NES-16263 Verify completed scan shows result in 3 tabs - Summary, Records, & History")
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=created_scan)
        scan_page = ScansPage()
        try:
            wait(lambda: scan_page.is_element_present("bd_scan_summary_tab"),
                 waiting_for="Waiting for Scan summary tab of the completed scan")
            scan_page.bd_scan_summary_tab.click()
            log.info("The Summary tab is available in the completed BD scan")
        except:
            assert False, 'The Summary tab is NOT available in the completed BD scan'
        try:
            wait(lambda: scan_page.is_element_present("bd_records_tab"),
                 waiting_for="Waiting for Records tab of the completed scan")
            scan_page.bd_records_tab.click()
            log.info("The Records tab is available in the completed BD scan")
        except:
            assert False, 'The Records tab is NOT available in the completed BD scan'
        try:
            wait(lambda: scan_page.is_element_present("history_tab"),
                 waiting_for="Waiting for History tab of the completed scan")
            scan_page.history_tab.click()
            log.info("The History tab is available in the completed BD scan")
        except:
            assert False, 'The History tab is NOT available in the completed BD scan'

    @pytest.mark.xray(test_key='NES-16315')
    @pytest.mark.xray(test_key='NES-16264')
    @pytest.mark.xray(test_key='NES-16263')
    @pytest.mark.order(3)
    @pytest.mark.parametrize("create_scan_bit_discovery",
                             [{'template_name': Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY,
                               'scan_type': API.Permissions.Types.SCANNER,
                               'domain_name': 'tenablenetworksecurity.com'}], indirect=True)
    def test_attack_surface_discovery_verify_scan_results(self, create_scan_bit_discovery):
        """
        NES-16315 Verify BitDiscovery scan
        NES-16264 Verify completed scan shows proper records in the Records tab
        NES-16263 Verify completed scan shows result in 3 tabs - Summary, Records, & History
        Check the details once the scan gets completed
        Steps:
        1. Create a scan config using the attack surface discovery template
        2. Launch the saved scan config
        3. Verify that the scan gets completed.
        4. Once completed check the tabs available in the result
        """
        created_scan = create_scan_bit_discovery
        result = scan_save_launch_and_status_verification(scan_name=created_scan,
                                                          scan_status=API.Scan.Status.COMPLETED,
                                                          scan_folder_name=Nessus.Scan.Folder.MY_SCANS)
        assert result, "The scan did not get complete"
        log.info("The attack surface scan gets completed.")
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=created_scan)
        scan_page = ScansPage()
        try:
            wait(lambda: scan_page.is_element_present("bd_scan_summary_tab"),
                 waiting_for="Waiting for Scan summary tab of the completed scan")
            scan_page.bd_scan_summary_tab.click()
            log.info("The Summary tab is available in the completed BD scan")
        except:
            assert False, 'The Summary tab is NOT available in the completed BD scan'
        assert scan_page.bd_domain_name.text == "tenablenetworksecurity.com", \
            "The domain name value is either not visible in summary page or it is wrong"
        log.info("The domain name value is fine")
        record_value_summary_page = scan_page.bd_record_count.text
        assert scan_page.bd_record_count.text, "The record count value is either 0 or null"
        try:
            wait(lambda: scan_page.is_element_present("bd_records_tab"),
                 waiting_for="Waiting for Records tab of the completed scan")
            scan_page.bd_records_tab.click()
            log.info("The Records tab is available in the completed BD scan")
        except:
            assert False, 'The Records tab is NOT available in the completed BD scan'
        assert scan_page.bd_record_tab_policy.text == "Attack Surface Discovery", "Policy value is incorrect"
        assert scan_page.bd_record_tab_scan_status.text == "Completed", "The scan has not been completed"
        assert f" of {Nessus.About.DEF_ASD_DOMAINS} domains remaining" in\
               scan_page.bd_record_tab_license_status.text, "The license status is improper"
        assert record_value_summary_page == scan_page.bd_record_tab_records_value.text, \
            "Records in the summary page not matching"

    @pytest.mark.order(4)
    @pytest.mark.parametrize("create_scan_bit_discovery",
                             [{'template_name': Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY,
                               'scan_type': API.Permissions.Types.SCANNER,
                               'domain_name': 'tenablenetworksecurity.com'}], indirect=True)
    def test_asd_filtering_of_ip_address_equal_to(self, create_scan_bit_discovery):
        """
        Check the filtered details once the scan gets completed
        Steps:
        1. Once the scan gets completed check IP address filter
        2. Use Not Equal to filter
        """
        created_scan = create_scan_bit_discovery
        result = scan_save_launch_and_status_verification(scan_name=created_scan,
                                                          scan_status=API.Scan.Status.COMPLETED,
                                                          scan_folder_name=Nessus.Scan.Folder.MY_SCANS)
        assert result, "The scan did not get complete"
        log.info("The attack surface scan gets completed.")
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=created_scan)
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("bd_scan_summary_tab"),
             waiting_for="Waiting for Scan summary tab of the completed scan")
        scan_page.bd_scan_summary_tab.click()

        wait(lambda: scan_page.is_element_present("bd_records_tab"),
             waiting_for="Waiting for Records tab of the completed scan")
        scan_page.bd_records_tab.click()

        host_list = ScansASDHostsList()
        rows = host_list.get_all()
        data = {row[Nessus.Filter.FilterKeys.IP_ADDRESS] for row in rows}
        data = list(dict.fromkeys(data))
        filter_type = Nessus.Filter.FilterKeys.IP_ADDRESS
        FilterModal.add_and_apply_to_filter(
            key=filter_type,
            operator=Nessus.Filter.FilterOperators.EQUAL_TO,
            value=data[0]
        )
        rows = host_list.get_all()
        filtered_data = [row[Nessus.Filter.FilterKeys.IP_ADDRESS] for row in rows]
        result = str(data[0])
        bad_result = str(data[1])
        assert result in filtered_data, f"Could not find the result '{result}' in the list of results"
        assert bad_result not in filtered_data, f"Should not have found the result '{bad_result}' in list of results"

    @pytest.mark.order(5)
    @pytest.mark.parametrize("create_scan_bit_discovery",
                             [{'template_name': Nessus.TemplateNames.ATTACK_SURFACE_DISCOVERY,
                               'scan_type': API.Permissions.Types.SCANNER,
                               'domain_name': 'tenablenetworksecurity.com'}], indirect=True)
    def test_asd_filtering_of_ip_address_not_equal(self, create_scan_bit_discovery):
        """
        Check the filtered details once the scan gets completed
        Steps:
        1. Once the scan gets completed check IP address filter
        2. Use Not Equal to filter
        """
        created_scan = create_scan_bit_discovery
        result = scan_save_launch_and_status_verification(scan_name=created_scan,
                                                          scan_status=API.Scan.Status.COMPLETED,
                                                          scan_folder_name=Nessus.Scan.Folder.MY_SCANS)
        assert result, "The scan did not get complete"
        log.info("The attack surface scan gets completed.")
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=created_scan)
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("bd_scan_summary_tab"),
             waiting_for="Waiting for Scan summary tab of the completed scan")
        scan_page.bd_scan_summary_tab.click()

        wait(lambda: scan_page.is_element_present("bd_records_tab"),
             waiting_for="Waiting for Records tab of the completed scan")
        scan_page.bd_records_tab.click()

        host_list = ScansASDHostsList()
        rows = host_list.get_all()
        data = {row[Nessus.Filter.FilterKeys.IP_ADDRESS] for row in rows}
        data = list(dict.fromkeys(data))
        filter_type = Nessus.Filter.FilterKeys.IP_ADDRESS
        FilterModal.add_and_apply_to_filter(
            key=filter_type,
            operator=Nessus.Filter.FilterOperators.NOT_EQUAL_TO,
            value=data[0]
        )
        rows = host_list.get_all()
        filtered_data = [row[Nessus.Filter.FilterKeys.IP_ADDRESS] for row in rows]
        result = str(data[1])
        bad_result = str(data[0])
        assert result in filtered_data, f"Could not find the result '{result}' in the list of results"
        assert bad_result not in filtered_data, f"Should not have found the result '{bad_result}' in list of results"