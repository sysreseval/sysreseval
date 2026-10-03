"""Fixture lab for the instructor-mode tests of tests/test_functional.py: instructor() texts in
the informations, in a text question (title and description) and in a form question."""
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0, instructor, make_tr

tr = make_tr('en')

allow_save_restore = True


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)


class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = instructor(tr("""
            ## Solution
            Run `ip route add default via 10.0.0.1` on the client.
            """, fr="""
            ## Solution
            Lancer `ip route add default via 10.0.0.1` sur le client.
            """)) + tr("""
            Configure the default route of the client.
            """, fr="""
            Configurer la route par défaut du client.
            """)


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='route', grade=0, max_grade=1)
        self.question_text(
            title=tr("Gateway", fr="Passerelle") + instructor(tr(" (expected: 10.0.0.1)", fr=" (attendu : 10.0.0.1)")),
            description=tr("Which gateway does the client use?") + instructor(tr("\n\nAny notation is fine.")))
        self.question_form(
            title=tr("Mask"),
            description=instructor(tr("The mask is 24.\n\n")) + tr("Prefix length: @@{mask:[0-9]+}@@"))
