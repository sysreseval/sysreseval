"""Tests for Data0 serialization, ips/nets/macs containers, type enforcement, and Flavor0."""
import json
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

import pytest
from netaddr import EUI

from SRE.lib_sre import Data0, Flavor0


# ---------------------------------------------------------------------------
# Minimal concrete subclasses used across these tests
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class SimpleData(Data0):
    value: int = 0
    name: str = ''

    @classmethod
    def generate(cls):
        return cls(value=42, name='test')


@dataclass(slots=True)
class NestedData(Data0):
    inner: SimpleData = None
    count: int = 0

    @classmethod
    def generate(cls):
        return cls(inner=SimpleData(value=7, name='inner'), count=3)


# ---------------------------------------------------------------------------
# ips / nets auto-injection
# ---------------------------------------------------------------------------

class TestContainersInjected:
    def test_ips_and_nets_present_after_init(self):
        d = SimpleData()
        assert hasattr(d, 'ips')
        assert hasattr(d, 'nets')
        assert hasattr(d, 'macs')

    def test_ips_empty_by_default(self):
        d = SimpleData()
        assert d.ips.__dict__ == {}
        assert d.nets.__dict__ == {}
        assert d.macs.__dict__ == {}

    def test_ips_type_enforcement(self):
        d = SimpleData()
        with pytest.raises(TypeError):
            d.ips.router = '192.168.1.1'       # str not accepted

    def test_nets_type_enforcement(self):
        d = SimpleData()
        with pytest.raises(TypeError):
            d.nets.lan = '10.0.0.0/24'         # str not accepted

    def test_ips_accepts_ipv4interface(self):
        d = SimpleData()
        d.ips.router = IPv4Interface('192.168.1.1/24')
        assert d.ips.router == IPv4Interface('192.168.1.1/24')

    def test_nets_accepts_ipv4network(self):
        d = SimpleData()
        d.nets.lan = IPv4Network('10.0.0.0/24')
        assert d.nets.lan == IPv4Network('10.0.0.0/24')

    def test_macs_type_enforcement(self):
        d = SimpleData()
        with pytest.raises(TypeError):
            d.macs.m1 = '00:1a:2b:3c:4d:5e'   # str not accepted

    def test_macs_rejects_int(self):
        d = SimpleData()
        with pytest.raises(TypeError):
            d.macs.m1 = 0x001a2b3c4d5e

    def test_macs_accepts_eui(self):
        d = SimpleData()
        d.macs.m1 = EUI('00:1a:2b:3c:4d:5e')
        assert d.macs.m1 == EUI('00:1a:2b:3c:4d:5e')

    def test_macs_multiple_attributes(self):
        d = SimpleData()
        d.macs.m1 = EUI('aa:bb:cc:dd:ee:ff')
        d.macs.m2 = EUI('11:22:33:44:55:66')
        assert len(d.macs.__dict__) == 2


# ---------------------------------------------------------------------------
# to_dict / from_dict
# ---------------------------------------------------------------------------

class TestDictRoundtrip:
    def test_basic_fields(self):
        d = SimpleData(value=10, name='hello')
        d2 = SimpleData.from_dict(d.to_dict())
        assert d2.value == 10
        assert d2.name == 'hello'

    def test_ips_preserved(self):
        d = SimpleData()
        d.ips.gw = IPv4Interface('172.16.0.1/24')
        d2 = SimpleData.from_dict(d.to_dict())
        assert d2.ips.gw == IPv4Interface('172.16.0.1/24')

    def test_nets_preserved(self):
        d = SimpleData()
        d.nets.mgmt = IPv4Network('172.16.0.0/16')
        d2 = SimpleData.from_dict(d.to_dict())
        assert d2.nets.mgmt == IPv4Network('172.16.0.0/16')

    def test_macs_preserved(self):
        d = SimpleData()
        d.macs.m1 = EUI('00:1a:2b:3c:4d:5e')
        d2 = SimpleData.from_dict(d.to_dict())
        assert d2.macs.m1 == EUI('00:1a:2b:3c:4d:5e')

    def test_multiple_macs(self):
        d = SimpleData()
        d.macs.m1 = EUI('aa:bb:cc:dd:ee:ff')
        d.macs.m2 = EUI('11:22:33:44:55:66')
        d2 = SimpleData.from_dict(d.to_dict())
        assert d2.macs.m1 == EUI('aa:bb:cc:dd:ee:ff')
        assert d2.macs.m2 == EUI('11:22:33:44:55:66')

    def test_macs_empty_by_default_in_dict(self):
        d = SimpleData()
        assert d.to_dict()['macs'] == {}

    def test_multiple_ips_and_nets(self):
        d = SimpleData()
        d.ips.a = IPv4Interface('1.2.3.4/24')
        d.ips.b = IPv4Interface('5.6.7.8/16')
        d.nets.x = IPv4Network('192.168.0.0/24')
        d.nets.y = IPv4Network('10.0.0.0/8')
        d2 = SimpleData.from_dict(d.to_dict())
        assert d2.ips.a == IPv4Interface('1.2.3.4/24')
        assert d2.ips.b == IPv4Interface('5.6.7.8/16')
        assert d2.nets.x == IPv4Network('192.168.0.0/24')
        assert d2.nets.y == IPv4Network('10.0.0.0/8')

    def test_nested_data0(self):
        d = NestedData.generate()
        d2 = NestedData.from_dict(d.to_dict())
        assert isinstance(d2.inner, SimpleData)
        assert d2.inner.value == 7
        assert d2.count == 3


# ---------------------------------------------------------------------------
# to_json / from_json
# ---------------------------------------------------------------------------

class TestJsonRoundtrip:
    def test_polymorphic_from_json(self):
        """Data0.from_json resolves the concrete class via the registry."""
        d = SimpleData(value=99, name='roundtrip')
        d.ips.gw = IPv4Interface('172.16.0.1/24')
        d2 = Data0.from_json(d.to_json())
        assert isinstance(d2, SimpleData)
        assert d2.value == 99
        assert d2.ips.gw == IPv4Interface('172.16.0.1/24')

    def test_json_contains_type_key(self):
        import json
        d = SimpleData(value=1)
        obj = json.loads(d.to_json())
        assert '__type__' in obj
        assert 'data' in obj

    def test_nested_json_roundtrip(self):
        d = NestedData.generate()
        d.inner.ips.host = IPv4Interface('10.0.0.10/24')
        d2 = Data0.from_json(d.to_json())
        assert d2.inner.value == 7


# ---------------------------------------------------------------------------
# pack / unpack (msgpack)
# ---------------------------------------------------------------------------

class TestMsgpackRoundtrip:
    def test_basic(self):
        d = SimpleData(value=5, name='packed')
        d.ips.host = IPv4Interface('10.0.0.5/24')
        blob = d.pack()
        d2 = Data0.unpack(blob)
        assert isinstance(d2, SimpleData)
        assert d2.value == 5
        assert d2.ips.host == IPv4Interface('10.0.0.5/24')

    def test_macs_preserved(self):
        d = SimpleData(value=3, name='packed')
        d.macs.m1 = EUI('de:ad:be:ef:00:01')
        blob = d.pack()
        d2 = Data0.unpack(blob)
        assert d2.macs.m1 == EUI('de:ad:be:ef:00:01')

    def test_empty_ips_nets(self):
        d = SimpleData(value=0, name='')
        blob = d.pack()
        d2 = Data0.unpack(blob)
        assert d2.ips.__dict__ == {}
        assert d2.nets.__dict__ == {}
        assert d2.macs.__dict__ == {}


# ---------------------------------------------------------------------------
# Flavor0 subclasses used across flavor tests
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class SimpleFlavor(Flavor0):
    level: int = 0
    name: str = ''


@dataclass(slots=True)
class BoolFlavor(Flavor0):
    enabled: bool = False
    count: int = 0


@dataclass(slots=True)
class RestrictedFlavor(Flavor0):
    nb: int = 0

    def allowed_by_user(self):
        if self.nb < 10:
            return True, ""
        return False, "too high"


# ---------------------------------------------------------------------------
# Flavor0 registry
# ---------------------------------------------------------------------------

class TestFlavorRegistry:
    def test_subclass_registered(self):
        key = f"{SimpleFlavor.__module__}.{SimpleFlavor.__qualname__}"
        assert key in Flavor0._registry
        assert Flavor0._registry[key] is SimpleFlavor

    def test_type_key_attribute(self):
        assert SimpleFlavor._type_key == f"{SimpleFlavor.__module__}.{SimpleFlavor.__qualname__}"

    def test_multiple_subclasses_registered_independently(self):
        key1 = f"{SimpleFlavor.__module__}.{SimpleFlavor.__qualname__}"
        key2 = f"{BoolFlavor.__module__}.{BoolFlavor.__qualname__}"
        assert Flavor0._registry[key1] is SimpleFlavor
        assert Flavor0._registry[key2] is BoolFlavor


# ---------------------------------------------------------------------------
# Flavor0 to_dict / from_dict
# ---------------------------------------------------------------------------

class TestFlavorDictRoundtrip:
    def test_basic_fields(self):
        f = SimpleFlavor(level=3, name='hard')
        d = f.to_dict()
        assert d['level'] == 3
        assert d['name'] == 'hard'

    def test_from_dict_restores_fields(self):
        f = SimpleFlavor(level=7, name='easy')
        f2 = SimpleFlavor.from_dict(f.to_dict())
        assert f2.level == 7
        assert f2.name == 'easy'

    def test_bool_field_roundtrip(self):
        f = BoolFlavor(enabled=True, count=5)
        f2 = BoolFlavor.from_dict(f.to_dict())
        assert f2.enabled is True
        assert f2.count == 5

    def test_default_values(self):
        f = SimpleFlavor()
        f2 = SimpleFlavor.from_dict(f.to_dict())
        assert f2.level == 0
        assert f2.name == ''


# ---------------------------------------------------------------------------
# Flavor0 from_form_dict: type coercion
# ---------------------------------------------------------------------------

class TestFlavorFromFormDict:
    def test_int_coerced_from_string(self):
        f = SimpleFlavor.from_form_dict({'level': '5', 'name': 'x'})
        assert f.level == 5
        assert isinstance(f.level, int)

    def test_string_field_unchanged(self):
        f = SimpleFlavor.from_form_dict({'level': '0', 'name': 'hello'})
        assert f.name == 'hello'

    def test_bool_true_variants(self):
        for val in ('true', 'True', '1', 'yes'):
            f = BoolFlavor.from_form_dict({'enabled': val, 'count': '0'})
            assert f.enabled is True, f"Expected True for {val!r}"

    def test_bool_false_variants(self):
        for val in ('false', 'False', '0', 'no'):
            f = BoolFlavor.from_form_dict({'enabled': val, 'count': '0'})
            assert f.enabled is False, f"Expected False for {val!r}"

    def test_already_correct_type_not_recoerced(self):
        f = SimpleFlavor.from_form_dict({'level': 9, 'name': 'ok'})
        assert f.level == 9

    def test_extra_keys_set_as_attributes(self):
        f = SimpleFlavor.from_form_dict({'level': '1', 'name': 'x', 'option2': 'B'})
        assert f.option2 == 'B'

    def test_extra_keys_not_in_dataclass_fields(self):
        from dataclasses import fields
        f = SimpleFlavor.from_form_dict({'level': '1', 'name': 'x', 'extra': 'val'})
        field_names = {field.name for field in fields(SimpleFlavor)}
        assert 'extra' not in field_names
        assert f.extra == 'val'

    def test_missing_keys_use_defaults(self):
        f = SimpleFlavor.from_form_dict({'level': '3'})
        assert f.name == ''   # default preserved


# ---------------------------------------------------------------------------
# Flavor0 allowed_by_user
# ---------------------------------------------------------------------------

class TestFlavorAllowedByUser:
    def test_default_always_allowed(self):
        f = SimpleFlavor(level=0)
        ok, msg = f.allowed_by_user()
        assert ok is True
        assert msg == ""

    def test_override_allowed(self):
        f = RestrictedFlavor(nb=5)
        ok, msg = f.allowed_by_user()
        assert ok is True
        assert msg == ""

    def test_override_denied(self):
        f = RestrictedFlavor(nb=10)
        ok, msg = f.allowed_by_user()
        assert ok is False
        assert msg != ""

    def test_boundary_just_below_limit(self):
        f = RestrictedFlavor(nb=9)
        ok, _ = f.allowed_by_user()
        assert ok is True

    def test_boundary_at_limit(self):
        f = RestrictedFlavor(nb=10)
        ok, _ = f.allowed_by_user()
        assert ok is False


# ---------------------------------------------------------------------------
# Helpers for hook tests
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class HookedData(Data0):
    """Concrete Data0 subclass that records compute_pre/post_generate calls."""
    value: int = 0

    @classmethod
    def generate(cls, flavor=None):
        return cls(value=7)

    @classmethod
    def compute_pre_generate(cls, flavor=None):
        cls._pre_calls.append(flavor)

    def compute_post_generate(self):
        type(self)._post_calls.append(self.value)


HookedData._pre_calls = []
HookedData._post_calls = []


@dataclass(slots=True)
class WrapperData(Data0):
    """Outer Data0 that embeds a HookedData field to test nested behaviour."""
    inner: HookedData = None

    @classmethod
    def generate(cls):
        return cls(inner=HookedData(value=99))


@pytest.fixture(autouse=False)
def clear_hook_calls():
    """Reset HookedData call logs before each hook test."""
    HookedData._pre_calls.clear()
    HookedData._post_calls.clear()
    yield


# ---------------------------------------------------------------------------
# compute_pre_generate / compute_post_generate — default no-ops
# ---------------------------------------------------------------------------

class TestComputeHooksDefaults:
    def test_pre_default_noop(self):
        d = SimpleData(value=1)
        assert SimpleData.compute_pre_generate(None) is None

    def test_post_default_noop(self):
        d = SimpleData(value=1)
        assert d.compute_post_generate() is None

    def test_pre_default_accepts_flavor(self):
        f = SimpleFlavor(level=1)
        assert SimpleData.compute_pre_generate(f) is None


# ---------------------------------------------------------------------------
# compute_pre_generate / compute_post_generate — called by from_json
# ---------------------------------------------------------------------------

class TestComputeHooksFromJson:
    def test_both_hooks_called(self, clear_hook_calls):
        d = HookedData(value=3)
        Data0.from_json(d.to_json())
        assert len(HookedData._pre_calls) == 1
        assert len(HookedData._post_calls) == 1

    def test_pre_called_before_post(self, clear_hook_calls):
        order = []
        original_pre = HookedData.compute_pre_generate
        original_post = HookedData.compute_post_generate
        HookedData.compute_pre_generate = classmethod(lambda cls, flavor=None: order.append('pre'))
        HookedData.compute_post_generate = lambda self: order.append('post')
        try:
            Data0.from_json(HookedData(value=1).to_json())
        finally:
            HookedData.compute_pre_generate = original_pre
            HookedData.compute_post_generate = original_post
        assert order == ['pre', 'post']

    def test_pre_receives_none_when_no_flavor(self, clear_hook_calls):
        d = HookedData(value=5)
        Data0.from_json(d.to_json())
        assert HookedData._pre_calls[0] is None

    def test_pre_receives_flavor_when_present(self, clear_hook_calls):
        d = HookedData(value=5)
        f = SimpleFlavor(level=9, name='x')
        object.__setattr__(d, 'flavor', f)
        Data0.from_json(d.to_json())
        received = HookedData._pre_calls[0]
        assert isinstance(received, SimpleFlavor)
        assert received.level == 9

    def test_post_sees_correct_field_value(self, clear_hook_calls):
        d = HookedData(value=42)
        Data0.from_json(d.to_json())
        assert HookedData._post_calls[0] == 42

    def test_nested_data_does_not_trigger_outer_hooks(self, clear_hook_calls):
        """HookedData embedded in a WrapperData must not fire HookedData hooks."""
        w = WrapperData(inner=HookedData(value=99))
        Data0.from_json(w.to_json())
        assert HookedData._pre_calls == []
        assert HookedData._post_calls == []

    def test_from_dict_alone_does_not_call_hooks(self, clear_hook_calls):
        d = HookedData(value=3)
        HookedData.from_dict(d.to_dict())
        assert HookedData._pre_calls == []
        assert HookedData._post_calls == []


# ---------------------------------------------------------------------------
# compute_pre_generate / compute_post_generate — called by load_from_json_file
# ---------------------------------------------------------------------------

class TestComputeHooksLoadFromJsonFile:
    def test_both_hooks_called(self, clear_hook_calls, tmp_path):
        path = tmp_path / "data.json"
        d = HookedData(value=11)
        d.save_to_json_file(path)
        Data0.load_from_json_file(path)
        assert len(HookedData._pre_calls) == 1
        assert len(HookedData._post_calls) == 1

    def test_pre_receives_flavor(self, clear_hook_calls, tmp_path):
        path = tmp_path / "data.json"
        d = HookedData(value=11)
        f = SimpleFlavor(level=3, name='y')
        object.__setattr__(d, 'flavor', f)
        d.save_to_json_file(path)
        Data0.load_from_json_file(path)
        received = HookedData._pre_calls[0]
        assert isinstance(received, SimpleFlavor)
        assert received.level == 3

    def test_post_sees_correct_value(self, clear_hook_calls, tmp_path):
        path = tmp_path / "data.json"
        HookedData(value=77).save_to_json_file(path)
        Data0.load_from_json_file(path)
        assert HookedData._post_calls[0] == 77


# ---------------------------------------------------------------------------
# compute_pre_generate / compute_post_generate — called by unpack
# ---------------------------------------------------------------------------

class TestComputeHooksUnpack:
    def test_both_hooks_called(self, clear_hook_calls):
        blob = HookedData(value=8).pack()
        Data0.unpack(blob)
        assert len(HookedData._pre_calls) == 1
        assert len(HookedData._post_calls) == 1

    def test_pre_receives_none_flavor(self, clear_hook_calls):
        blob = HookedData(value=8).pack()
        Data0.unpack(blob)
        assert HookedData._pre_calls[0] is None

    def test_pre_receives_flavor_when_present(self, clear_hook_calls):
        d = HookedData(value=8)
        f = SimpleFlavor(level=5, name='z')
        object.__setattr__(d, 'flavor', f)
        Data0.unpack(d.pack())
        received = HookedData._pre_calls[0]
        assert isinstance(received, SimpleFlavor)
        assert received.level == 5

    def test_post_sees_correct_value(self, clear_hook_calls):
        Data0.unpack(HookedData(value=55).pack())
        assert HookedData._post_calls[0] == 55


# ---------------------------------------------------------------------------
# Helpers for flavor / lifecycle tests
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class PreGenData(Data0):
    """Records what flavor compute_pre_generate received; stores topology class-attr."""
    value: int = 0

    @classmethod
    def compute_pre_generate(cls, flavor=None):
        size = flavor.level if flavor is not None else 0
        cls.topology = {'net0': list(range(size))}
        cls.machine_specs = {f'm{i}': {} for i in range(size)}


@dataclass(slots=True)
class PostGenData(Data0):
    """Sets a derived instance attr in compute_post_generate."""
    value: int = 0

    def compute_post_generate(self):
        object.__setattr__(self, 'doubled', self.value * 2)


@dataclass(slots=True)
class DynAttrData(Data0):
    """Sets topology/machine_specs as dynamic instance attrs in generate()."""
    @classmethod
    def generate(cls, flavor=None):
        data = cls()
        data.topology = {'net0': ['m1', 'm2']}
        data.machine_specs = {'m1': {}, 'm2': {}}
        return data


@dataclass(slots=True)
class DeclaredFieldData(Data0):
    """Declares topology as a real dataclass field so it IS serialised."""
    topology: dict = None

    @classmethod
    def generate(cls):
        data = cls()
        data.topology = {'net0': ['m1']}
        return data


# ---------------------------------------------------------------------------
# Flavor lifecycle: state at each stage
# ---------------------------------------------------------------------------

class TestFlavorLifecycle:
    def test_flavor_none_by_default_after_init(self):
        """Fresh Data0 instance always has flavor=None from __post_init__."""
        d = SimpleData(value=1)
        assert d.flavor is None

    def test_flavor_none_after_generate_when_not_stored(self):
        """generate() that uses flavor locally but doesn't store it leaves flavor=None."""
        @dataclass(slots=True)
        class LocalData(Data0):
            value: int = 0
            @classmethod
            def generate(cls, flavor=None):
                if flavor is None:
                    flavor = SimpleFlavor(level=3)
                return cls(value=flavor.level)  # flavor used but NOT stored

        data = LocalData.generate()
        assert data.flavor is None

    def test_flavor_accessible_after_explicit_store(self):
        """object.__setattr__ stores flavor; data.flavor then returns it."""
        d = SimpleData(value=1)
        f = SimpleFlavor(level=5, name='stored')
        object.__setattr__(d, 'flavor', f)
        assert d.flavor is f
        assert d.flavor.level == 5

    def test_flavor_absent_from_to_dict_when_none(self):
        """flavor=None is not written to to_dict output."""
        d = SimpleData(value=1)
        assert 'flavor' not in d.to_dict()

    def test_flavor_present_in_to_dict_when_set(self):
        """Stored flavor appears in to_dict output."""
        d = SimpleData(value=1)
        object.__setattr__(d, 'flavor', SimpleFlavor(level=2, name='x'))
        assert 'flavor' in d.to_dict()

    def test_flavor_survives_json_roundtrip(self):
        """Flavor stored on data is fully preserved through to_json → from_json."""
        d = HookedData(value=10)
        object.__setattr__(d, 'flavor', SimpleFlavor(level=7, name='round'))
        d2 = Data0.from_json(d.to_json())
        assert d2.flavor is not None
        assert isinstance(d2.flavor, SimpleFlavor)
        assert d2.flavor.level == 7
        assert d2.flavor.name == 'round'

    def test_compute_pre_generate_gets_none_when_flavor_not_stored(self, clear_hook_calls):
        """compute_pre_generate is called with None when data.flavor was not stored."""
        d = HookedData(value=3)
        assert d.flavor is None
        Data0.from_json(d.to_json())
        assert HookedData._pre_calls[0] is None

    def test_compute_pre_generate_gets_stored_flavor_after_roundtrip(self, clear_hook_calls):
        """compute_pre_generate receives the stored flavor on deserialization."""
        d = HookedData(value=3)
        f = SimpleFlavor(level=4, name='stored')
        object.__setattr__(d, 'flavor', f)
        Data0.from_json(d.to_json())
        received = HookedData._pre_calls[0]
        assert isinstance(received, SimpleFlavor)
        assert received.level == 4

    def test_flavor_survives_file_roundtrip(self, tmp_path):
        """Flavor stored on data survives save_to_json_file → load_from_json_file."""
        d = HookedData(value=20)
        object.__setattr__(d, 'flavor', SimpleFlavor(level=9, name='file'))
        path = tmp_path / 'data.json'
        d.save_to_json_file(path)
        d2 = Data0.load_from_json_file(path)
        assert isinstance(d2.flavor, SimpleFlavor)
        assert d2.flavor.level == 9

    def test_flavor_survives_msgpack_roundtrip(self):
        """Flavor stored on data survives pack → unpack."""
        d = HookedData(value=5)
        object.__setattr__(d, 'flavor', SimpleFlavor(level=3, name='pack'))
        d2 = Data0.unpack(d.pack())
        assert isinstance(d2.flavor, SimpleFlavor)
        assert d2.flavor.level == 3


# ---------------------------------------------------------------------------
# compute_pre_generate: class-level attributes
# ---------------------------------------------------------------------------

class TestComputePreGenerateClassAttrs:
    def test_class_attr_accessible_via_instance(self):
        """Class attr set by compute_pre_generate is readable through a data instance."""
        PreGenData.compute_pre_generate(SimpleFlavor(level=2))
        data = PreGenData()
        assert data.topology == {'net0': [0, 1]}
        assert data.machine_specs == {'m0': {}, 'm1': {}}

    def test_class_attr_not_in_instance_dict(self):
        """Class attrs from compute_pre_generate are NOT in the instance's __dict__."""
        PreGenData.compute_pre_generate(SimpleFlavor(level=1))
        data = PreGenData()
        assert 'topology' not in data.__dict__
        assert 'machine_specs' not in data.__dict__

    def test_class_attr_accessible_via_getattr(self):
        """getattr on the instance finds the class attr set by compute_pre_generate."""
        PreGenData.compute_pre_generate(SimpleFlavor(level=3))
        data = PreGenData()
        assert getattr(data, 'topology', None) is not None
        assert len(data.topology['net0']) == 3

    def test_class_attr_default_when_flavor_none(self):
        """compute_pre_generate(None) uses its own default (level=0 → empty topology)."""
        PreGenData.compute_pre_generate(None)
        data = PreGenData()
        assert data.topology == {'net0': []}

    def test_class_attr_restored_after_json_roundtrip(self):
        """Class attr is re-set by compute_pre_generate on deserialization."""
        data = PreGenData(value=1)
        f = SimpleFlavor(level=2)
        object.__setattr__(data, 'flavor', f)
        PreGenData.compute_pre_generate(f)

        data2 = Data0.from_json(data.to_json())
        # compute_pre_generate(SimpleFlavor(level=2)) was called → topology has 2 entries
        assert data2.topology == {'net0': [0, 1]}

    def test_class_attr_not_in_to_dict(self):
        """Class attrs are not declared fields and do not appear in to_dict."""
        PreGenData.compute_pre_generate(SimpleFlavor(level=1))
        data = PreGenData(value=5)
        assert 'topology' not in data.to_dict()
        assert 'machine_specs' not in data.to_dict()


# ---------------------------------------------------------------------------
# compute_post_generate: instance-level derived attributes
# ---------------------------------------------------------------------------

class TestComputePostGenerateInstanceAttrs:
    def test_instance_attr_set_by_post_generate(self):
        """compute_post_generate derives and stores an instance attr."""
        data = PostGenData(value=5)
        data.compute_post_generate()
        assert data.doubled == 10

    def test_instance_attr_in_instance_dict(self):
        """Dynamic instance attr from compute_post_generate is in __dict__."""
        data = PostGenData(value=3)
        data.compute_post_generate()
        assert 'doubled' in data.__dict__

    def test_instance_attr_not_in_to_dict(self):
        """Dynamic instance attr is not a declared field — absent from to_dict."""
        data = PostGenData(value=4)
        data.compute_post_generate()
        assert 'doubled' not in data.to_dict()

    def test_instance_attr_re_derived_after_json_roundtrip(self):
        """compute_post_generate runs on deserialization and re-sets the instance attr."""
        data = PostGenData(value=7)
        data2 = Data0.from_json(data.to_json())
        assert data2.doubled == 14

    def test_instance_attr_re_derived_after_file_roundtrip(self, tmp_path):
        """compute_post_generate runs after load_from_json_file."""
        path = tmp_path / 'data.json'
        PostGenData(value=6).save_to_json_file(path)
        data2 = Data0.load_from_json_file(path)
        assert data2.doubled == 12

    def test_instance_attr_re_derived_after_msgpack_roundtrip(self):
        """compute_post_generate runs after unpack."""
        data2 = Data0.unpack(PostGenData(value=8).pack())
        assert data2.doubled == 16


# ---------------------------------------------------------------------------
# generate(): dynamic instance attrs vs declared fields
# ---------------------------------------------------------------------------

class TestGenerateInstanceAttrs:
    def test_dynamic_attr_in_instance_dict(self):
        """Dynamic attr set in generate() lives in __dict__ on a slots Data."""
        data = DynAttrData.generate()
        assert 'topology' in data.__dict__
        assert data.topology == {'net0': ['m1', 'm2']}

    def test_dynamic_attr_accessible_via_getattr(self):
        """getattr finds dynamic instance attrs set in generate()."""
        data = DynAttrData.generate()
        assert getattr(data, 'topology', None) == {'net0': ['m1', 'm2']}
        assert getattr(data, 'machine_specs', None) == {'m1': {}, 'm2': {}}

    def test_dynamic_attr_not_in_to_dict(self):
        """Dynamic attrs set in generate() are NOT serialised (not declared fields)."""
        data = DynAttrData.generate()
        d = data.to_dict()
        assert 'topology' not in d
        assert 'machine_specs' not in d

    def test_declared_field_is_in_to_dict(self):
        """Declared dataclass field IS serialised by to_dict."""
        data = DeclaredFieldData.generate()
        assert data.to_dict()['topology'] == {'net0': ['m1']}

    def test_declared_field_survives_json_roundtrip(self):
        """Declared field survives to_json → from_json."""
        data = DeclaredFieldData.generate()
        data2 = Data0.from_json(data.to_json())
        assert isinstance(data2, DeclaredFieldData)
        assert data2.topology == {'net0': ['m1']}

    def test_declared_field_survives_file_roundtrip(self, tmp_path):
        """Declared field survives save_to_json_file → load_from_json_file."""
        path = tmp_path / 'data.json'
        DeclaredFieldData.generate().save_to_json_file(path)
        data2 = Data0.load_from_json_file(path)
        assert data2.topology == {'net0': ['m1']}

    def test_declared_field_survives_msgpack_roundtrip(self):
        """Declared field survives pack → unpack."""
        data2 = Data0.unpack(DeclaredFieldData.generate().pack())
        assert data2.topology == {'net0': ['m1']}
