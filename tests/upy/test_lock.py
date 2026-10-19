# SPDX-License-Identifier: GPL-3.0-only
"""R15: lock cancels workers and releases protocol/provider/store caches."""

from trezor import config, loop
from upytest import run, storage_setup, test

from feuristic.apps.backup import provider
from feuristic.apps.card.aes import keys
from feuristic.apps.card.openpgp import storage as pgp_storage
from feuristic.apps.card.piv import storage as piv_storage
from feuristic.apps.otp import accounts
from feuristic.fw import device, session, transports, usbmodes


@test
def lock_releases_state_and_reloads_fresh_providers():
    assert config.change_pin("1234", None)
    device.initialize()
    session._load_stores()
    assert accounts._default is None and pgp_storage._default is None
    assert piv_storage._default is None and keys._default is None
    assert not hasattr(provider.get("fido2"), "auth")
    server = transports.fido_server()
    session._register_fido_provider()
    assert len(provider.all()) == 5
    assert pgp_storage.default().ident is not None
    assert piv_storage.default().creds() is not None
    keys.default().load()

    async def pending():
        await loop.sleep(60_000)

    job = transports._spawn_worker(pending())
    assert not job.finished
    session.lock()
    assert job.finished and not transports._workers
    assert not config.is_unlocked()
    assert device._ms_cache is None
    assert transports._fido is None and transports._card is None
    assert provider.all() == []
    assert accounts._default is None and pgp_storage._default is None
    assert piv_storage._default is None and keys._default is None
    # The locked reader can only expose public RNG, without private applets.
    public = transports._card_obj()
    assert public.dispatcher.applets == []
    assert public.dispatcher.fallback.NAME == "rng"
    assert config.unlock("1234", None)
    session.reload_stores()
    assert transports.fido_server() is not server
    assert len(provider.all()) == 5


@test
def import_providers_do_not_rebuild_hid_and_release_only_store_caches():
    session._load_stores()
    proxies = provider.all()
    transports.on_lock()
    old_current = usbmodes.current
    usbmodes.current = lambda: usbmodes.IMPORT
    try:
        provider.get("fido2").list_identities()
        assert transports._fido is None
        provider.get("openpgp").list_identities()
        assert pgp_storage._default is not None
        provider.get("piv").list_identities()
        assert piv_storage._default is not None
        provider.get("aes").list_identities()
        provider.get("otp").list_identities()
        session.release_import_stores()
        assert provider.all() == proxies
        assert accounts._default is None and pgp_storage._default is None
        assert piv_storage._default is None and keys._default is None
        assert device.master_secret() is not None
    finally:
        usbmodes.current = old_current


storage_setup()
run()
