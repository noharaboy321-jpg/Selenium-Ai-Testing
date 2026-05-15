class TestConstants {
    Map windows10IpAddresses = [
        "10.8.3": [],
        "10.9.0": ['172.26.112.77'],
        "release": [],
        "release-next": [],
        "default": []
    ]
    Map windows11IpAddresses = [
        "10.8.3": [],
        "10.9.0": ['172.26.112.77'],
        "release": [],
        "release-next": [],
        "default": []
    ]
    Map windowsServer2019IpAddresses = [
        "10.8.3": [],
        "10.9.0": ['172.26.112.77'],
        "release": [],
        "release-next": [],
        "default": []
    ]
    Map windowsServer2022IpAddresses = [
        "10.8.3": [],
        "10.9.0": ['172.26.112.77'],
        "release": [],
        "release-next": [],
        "default": []
    ]
}

def createTestConstants() {
    new TestConstants()
}

return this
