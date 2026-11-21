"""Explicitly synthetic local demo: no student records, bank accounts or payments."""
import json
from wolfalibi.sector_profiles import SyntheticSectorGate, fake_owner, public_key, make_grant


def main():
    owner, agent = fake_owner(), fake_owner()
    owner_pub, agent_pub = public_key(owner), public_key(agent)
    gate = SyntheticSectorGate(owner_pub=owner_pub, agent_pub=agent_pub, tenant="synthetic-institution")
    core = {"tenant": "synthetic-institution", "agent_pub": agent_pub.hex(), "request_id": "example-A"}
    tutor = dict(core, profile="EDU_STUDENT_DATA_READ_V0", action="edu.tutor.respond",
                 resource="synthetic-lessons", args={"lesson": "math"})
    school = dict(core, profile="EDU_STUDENT_DATA_READ_V0", action="edu.student_record.read",
                  resource="synthetic-student-records", args={"student_ref":"student-A", "purpose":"approved-support"})
    pay = dict(core, profile="FIN_PAYMENT_INITIATION_V0", action="fin.payment.initiate",
               resource="synthetic-payment-intents", args={"account_ref":"acct-A", "payee_ref":"payee-A",
                                                         "amount_minor":4500, "currency":"CAD"})
    now = 1000
    pay_grant = make_grant(owner, pay, grant_id="synthetic-payment-grant", role="account_owner",
                           not_before=now, expires_at=now+30)
    report = {"demo": "QUORVANE_SECTOR_PROFILES_001", "production": "BLOCKED", "cases": {
        "tutor":gate.evaluate(tutor,now=now),
        "student_record_without_grant":gate.evaluate(school,now=now),
        "payment_without_grant":gate.evaluate(pay,now=now),
        "payment_with_owner_grant":gate.evaluate(pay,grant=pay_grant,now=now),
        "payment_repeat":gate.evaluate(pay,grant=pay_grant,now=now),
    }}
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__=="__main__":main()
