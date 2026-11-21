"""Run the Gate 002 qualification on a clean Git revision using only local fixtures."""

import qualify_resource_gate as shared


BASE = "493629e346484a3a04c7b31fea6d18739a05346a"
INHERITED_COUNT = 291
EDUCATION_TEST_COUNT = 31
EDUCATION = shared.Gate("education", "002", BASE, 31, INHERITED_COUNT, EDUCATION_TEST_COUNT,
                        "committed_read_count", "HISTORICAL_SYNTHETIC_ADMISSION")


def demo_and_verifier(directory):
    return shared.demo_and_verifier(directory, EDUCATION)


def qualify(directory):
    return shared.qualify(directory, EDUCATION)


def main():
    return shared.main(EDUCATION, __doc__)


if __name__ == "__main__":
    raise SystemExit(main())
