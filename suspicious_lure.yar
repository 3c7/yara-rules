rule susp_lure_xls_WindowsInstaller_Feb2021_1 : suspicious xls lure thinbasic {
    meta:
        author = "Nils Kuhnert"
        date = "2022-02-26"
        description = "Triggers on docfiles executing windows installer. Used for deploying ThinBasic scripts."
        tlp = "white"
        reference = "https://inquest.net/blog/2022/02/24/dangerously-thinbasic"
        reference = "https://twitter.com/threatinsight/status/1497355737844133895"
    strings:
        $ = "WindowsInstaller.Installer$"
        $ = "CreateObject"
        $ = "InstallProduct"
    condition:
        uint32be(0) == 0xd0cf11e0 and all of them
}
