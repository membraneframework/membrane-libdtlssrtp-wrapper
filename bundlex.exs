defmodule Membrane.LibdtlssrtpWrapper.BundlexProject do
  use Bundlex.Project

  def project do
    [
      libs: libs()
    ]
  end

  defp libs do
    [
      libdtlssrtp: [
        sources: [
          "dsink_udp.c",
          "dtls_srtp.c"
        ],
        includes: ["/usr/local/opt/openssl/include"],
        lib_dirs: ["/usr/local/opt/openssl/lib"],
        libs: ["crypto", "ssl"]
      ]
    ]
  end
end
