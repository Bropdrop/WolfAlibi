def run(tools):
    record = tools["read_fixture"]()
    if record == b"WolfAlibi Stage 3 synthetic protected bytes\n":
        return True
    return False
