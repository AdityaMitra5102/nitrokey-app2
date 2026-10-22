import logging

from PySide6.QtCore import Signal, Slot

from nitrokeyapp.common_ui import CommonUi
from nitrokeyapp.device_data import DeviceData
from nitrokeyapp.update import UpdateGUI, UpdateResult
from nitrokeyapp.worker import Job, Worker
from nitrokeyapp.utils import get_transport
from nitrokeyapp.fido2_tab.worker import PinCache
from nitrokeyapp.fido2_tab.ui import Fido2PinUi, Fido2PinUiConnection
from nitrokey.trussed import Transport, Fido2Certs
from fido2.ctap2.pin import ClientPin
from typing import Optional
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from PySide6.QtCore import QEventLoop, Signal, Slot
from hashlib import sha256
from fido2.attestation.base import InvalidSignature
from fido2.attestation.packed import PackedAttestation
from fido2.client import PinRequiredError, UserInteraction, Fido2Client, WindowsClient
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AuthenticatorAttachment,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
    DefaultClientDataCollector
)
logger = logging.getLogger(__name__)


class UpdateDevice(Job):
    device_updated = Signal(UpdateResult)

    def __init__(self, common_ui: CommonUi, data: DeviceData, is_qubesos: bool) -> None:
        super().__init__(common_ui)

        self.data = data

        self.image: str | None = None
        self.is_qubesos = is_qubesos

        self.device_updated.connect(lambda _: self.finished.emit())

        self.update_gui = UpdateGUI(self.common_ui, data.model, self.is_qubesos)
        self.common_ui.prompt.confirmed.connect(self.cancel_busy_wait)

    def run(self) -> None:
        if not self.image:
            result = self.data.update(self.update_gui)
        else:
            result = self.data.update(self.update_gui, self.image)

        self.device_updated.emit(result)

    @Slot()
    def cleanup(self) -> None:
        self.common_ui.prompt.confirmed.disconnect()

    @Slot(bool)
    def cancel_busy_wait(self, confirmed: bool) -> None:
        self.update_gui.await_confirmation = confirmed

def verify_attestation(attestation_object: AttestationObject, client_data_hash: bytes) -> None:
        verifier = PackedAttestation()
        assert attestation_object.fmt == verifier.FORMAT
        verifier.verify(attestation_object.att_stmt, attestation_object.auth_data, client_data_hash)

class VerifyGenuine(Job):
    is_genuine = Signal(bool)

    def __init__(
        self,
        common_ui: CommonUi,
        data: DeviceData,
        pin_cache: PinCache,
        pin_ui: Fido2PinUi,
    ) -> None:
        super().__init__(common_ui)
        self.data = data
        self.pin_cache = pin_cache
        self.pin_ui = pin_ui
        self._pin_ui_conn: Fido2PinUiConnection | None = None

        self.is_genuine.connect(lambda _: self.finished.emit())

    def cleanup(self) -> None:
        if self._pin_ui_conn is not None:
            self._pin_ui_conn.disconnect()
            self._pin_ui_conn = None

    def _request_pin(self) -> str | None:
        cached = self.pin_cache.get(self.data)
        if cached is not None:
            return cached

        retries = self._get_pin_retries()
        if retries is None:
            self.trigger_error("FIDO2 PIN is not set on this device")
            return None

        loop = QEventLoop()
        result: list[str | None] = [None]

        def on_pin(pin: str) -> None:
            result[0] = pin
            loop.quit()

        def on_cancel() -> None:
            result[0] = None
            loop.quit()

        self._pin_ui_conn = self.pin_ui.connect_actions(on_pin, on_cancel)
        self.pin_ui.query.emit(retries)
        loop.exec()
        self.cleanup()
        pin = result[0]
        if self.pin_cache.get(self.data) is None:
            self.pin_cache.update(self.data, pin)
        return pin

    def _get_pin_retries(self) -> int | None:
        try:
            with self.data.open_ctap2() as ctap2:
                if not ctap2.info.options.get("clientPin"):
                    return None
                client_pin = ClientPin(ctap2)
                return client_pin.get_pin_retries()[0]
        except Exception as e:
            logger.warning(f"failed to get fido2 pin retries: {e}")
            return None

    def run(self) -> None:
        transport = get_transport()
        try:
            genuine = self._verify(transport)
        except Exception as e:
            self.trigger_error(f"Failed to verify device genuineness: {e}")
            return


        self.is_genuine.emit(genuine)

    def _verify(self, transport: Transport=Transport.CTAPHID) -> bool:
        get_pin = self._request_pin
        class Interaction(UserInteraction):
            def __init__(self):
                self._pin = None

            def prompt_up(self):
                pass

            def request_pin(self, permissions, rd_id):
                return get_pin()

            def request_uv(self, permissions, rd_id):
                return True
        
        client_data_collector = DefaultClientDataCollector(origin="https://example.com")
        if transport == Transport.CTAPHID:
            fido2_client = Fido2Client(device=self.data._device.connection.device, client_data_collector=client_data_collector, user_interaction=Interaction)
        else:
            fido2_client = WindowsClient(client_data_collector)

        firmware_version = self.data._device.admin.version()
        server = Fido2Server(
            PublicKeyCredentialRpEntity(id="example.com", name="Example RP"),
            attestation=AttestationConveyancePreference.DIRECT,
            verify_attestation=verify_attestation,
        )

        uv = UserVerificationRequirement.DISCOURAGED
        user = PublicKeyCredentialUserEntity(id=b"user_id", name="A. User")

        create_options, state = server.register_begin(
            user=user,
            user_verification=uv,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
        )
        make_credential_result = fido2_client.make_credential(create_options["publicKey"])
        cert = make_credential_result.response.attestation_object.att_stmt["x5c"]
        cert_hash = sha256(cert[0]).digest().hex()
        expected_certs = Fido2Certs.get(self.data._device.fido2_certs, firmware_version)
        if expected_certs and cert_hash in expected_certs.hashes:
            return True

        return False       


class OverviewWorker(Worker):
    # TODO: remove DeviceData from signatures
    device_updated = Signal(UpdateResult)

    def __init__(self, common_ui: CommonUi) -> None:
        super().__init__(common_ui)

    @Slot(DeviceData, bool)
    def update_device(self, data: DeviceData, is_qubesos: bool) -> None:
        job = UpdateDevice(self.common_ui, data, is_qubesos)
        job.device_updated.connect(self.device_updated)
        self.run(job)

    @Slot(DeviceData, str, bool)
    def update_device_file(self, data: DeviceData, filename: str, is_qubesos: bool) -> None:
        job = UpdateDevice(self.common_ui, data, is_qubesos)
        job.image = filename
        job.device_updated.connect(self.device_updated)
        self.run(job)
