import unittest

from plus_testkit.lan import LanClient
from plus_testkit.model import Deadline, ProbeError, ServerKey
from support import IDENTITY, OLD, Device


class LanTests(unittest.TestCase):
    def setUp(self):
        self.device = Device()
        self.addCleanup(self.device.close)
        self.client = LanClient(
            "127.0.0.1",
            port=self.device.port,
            allow_loopback=True,
            timeout=0.03,
            deadline=Deadline(5),
        )
        self.addCleanup(self.client.close)

    def test_real_loopback_identity_auth_and_read(self):
        identity = self.client.identify()
        self.assertEqual(identity.name, IDENTITY.name)
        self.client.authenticate(OLD.access(identity))
        self.assertEqual(self.client.read_power(), 0)

    def test_wrong_token_and_wrong_ack_mid_are_ignored(self):
        for fault in ["wrong_token", "wrong_mid"]:
            self.device.fault = fault
            self.client.identify()
        self.assertEqual(self.client.stats["discarded"], 2)

    def test_kernel_rejects_wrong_source_port(self):
        self.device.fault = "rogue_source"
        self.client.identify()
        self.assertEqual(self.client.stats["datagrams_received"], 1)

    def test_delayed_non_after_empty_ack(self):
        self.device.fault = "delayed_non"
        self.client.identify()
        self.assertEqual(self.client.stats["empty_acks"], 1)
        self.assertEqual(self.client.stats["datagrams_sent"], 1)

    def test_delayed_con_gets_transport_ack(self):
        self.device.fault = "delayed_con"
        self.client.identify()
        self.assertEqual(self.client.stats["acks_sent"], 1)

    def test_coap_404_is_preserved_not_timeout(self):
        self.device.fault = "error_404"
        with self.assertRaises(ProbeError) as raised:
            self.client.identify()
        self.assertEqual(raised.exception.public()["coap_code"], "4.04")

    def test_application_error_never_logs_response_body(self):
        self.client.identify()
        with self.assertRaises(ProbeError) as raised:
            self.client.authenticate(
                ServerKey("UNKNOWNX", "synthetic-secret").access(IDENTITY)
            )
        self.assertEqual(raised.exception.public()["application_code"], 502)
        self.assertEqual(str(raised.exception), "AUTH_REJECTED")

    def test_reset_is_distinct(self):
        self.device.fault = "reset"
        with self.assertRaisesRegex(ProbeError, "COAP_RESET"):
            self.client.identify()

    def test_no_power_write_or_raw_endpoint_api(self):
        self.client.identify()
        with self.assertRaisesRegex(ProbeError, "PATH_NOT_ALLOWED"):
            self.client._exchange("/sys/anything/thing/service/property/set", b"{}")
        self.assertEqual(self.device.writes, 0)

    def test_write_is_once_and_journal_callback_runs_before_server_receives_it(self):
        self.client.identify()
        self.client.authenticate(OLD.access(IDENTITY))
        order = []

        def before():
            self.assertEqual(self.device.writes, 0)
            order.append("durable")

        self.client.install(ServerKey("NEWSYNTH", "new-synthetic-secret"), before)
        self.assertEqual(order, ["durable"])
        with self.assertRaisesRegex(ProbeError, "WRITE_ALREADY_ATTEMPTED"):
            self.client.install(ServerKey("OTHERSYN", "other-synthetic-secret"), before)
        self.assertEqual(self.device.writes, 1)

    def test_write_not_sent_if_journal_callback_fails(self):
        self.client.identify()
        self.client.authenticate(OLD.access(IDENTITY))

        def fail():
            raise ProbeError("VAULT_SAVE_FAILED")

        with self.assertRaisesRegex(ProbeError, "VAULT_SAVE_FAILED"):
            self.client.install(ServerKey("NEWSYNTH", "new-synthetic-secret"), fail)
        self.assertEqual(self.device.writes, 0)

    def test_production_client_rejects_loopback_and_non_lan_targets(self):
        for host in ["127.0.0.1", "8.8.8.8", "0.0.0.0", "224.0.1.187", "example.com"]:
            with self.subTest(host=host), self.assertRaises(ProbeError):
                LanClient(host)

    def test_server_proof_is_required_before_accepting_session(self):
        self.client.identify()
        self.device.fault = "bad_server_proof"
        with self.assertRaisesRegex(ProbeError, "SERVER_PROOF_INVALID"):
            self.client.authenticate(OLD.access(IDENTITY))
        self.assertIsNone(self.client.session)

    def test_authenticated_response_rejects_wrong_sid_checksum_ciphertext_and_json_id(
        self,
    ):
        self.client.identify()
        self.client.authenticate(OLD.access(IDENTITY))
        for fault in [
            "bad_sid",
            "bad_checksum",
            "bad_ciphertext",
            "wrong_json_id",
            "duplicate_session",
        ]:
            self.device.fault = fault
            with self.subTest(fault=fault), self.assertRaises(ProbeError):
                self.client.read_power()
        self.assertEqual(self.device.writes, 0)

    def test_block2_unknown_critical_and_bad_format_fail_closed(self):
        for fault, reason in [
            ("block2", "BLOCK2_UNSUPPORTED"),
            ("critical_option", "CRITICAL_OPTION_UNSUPPORTED"),
            ("bad_format", "CONTENT_FORMAT_UNSUPPORTED"),
        ]:
            self.device.fault = fault
            with self.subTest(fault=fault), self.assertRaisesRegex(ProbeError, reason):
                self.client.identify()

    def test_persistent_silence_has_bounded_read_retransmissions(self):
        self.device.silent = True
        with self.assertRaisesRegex(ProbeError, "TIMEOUT"):
            self.client.identify()
        self.assertEqual(self.client.stats["datagrams_sent"], 2)

    def test_empty_ack_alone_is_not_success_and_suppresses_retransmission(self):
        self.device.fault = "empty_ack_only"
        with self.assertRaisesRegex(ProbeError, "TIMEOUT"):
            self.client.identify()
        self.assertEqual(self.client.stats["datagrams_sent"], 1)
        self.assertEqual(self.client.stats["empty_acks"], 1)
