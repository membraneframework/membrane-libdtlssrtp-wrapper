defmodule Membrane.LibdtlssrtpWrapper.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :membrane_libdtlssrtp_wrapper,
      version: @version,
      elixir: "~> 1.9",
      compilers: [:bundlex] ++ Mix.compilers(),
      deps: deps()
    ]
  end

  defp deps do
    [
      {:bundlex, "~> 0.2.7"}
    ]
  end
end
