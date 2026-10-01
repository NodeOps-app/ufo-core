from ufo.sdk.manifest import Manifest
from ufo.sdk.sandbox import CarrierSpec
from ufo_ext_createos.carrier import API_KEY_ENV, NAME, CreateOSCarrier


def manifest() -> Manifest:
    return Manifest(
        name=NAME,
        version="0.1.0",
        deploy_keys=(API_KEY_ENV,),
        carriers=(CarrierSpec(name=NAME, factory=CreateOSCarrier.from_env, off_cluster=True),),
    )
