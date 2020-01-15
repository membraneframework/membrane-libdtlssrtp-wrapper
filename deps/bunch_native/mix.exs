defmodule Bunch.Native.Mixfile do
  use Mix.Project

  @version "0.2.1"
  @github_url "https://github.com/membraneframework/bunch-native"

  def project do
    [
      app: :bunch_native,
      version: @version,
      elixir: "~> 1.7",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: [:bundlex] ++ Mix.compilers(),
      description: "Native part of the Bunch package",
      package: package(),
      name: "Bunch Native",
      source_url: @github_url,
      docs: docs(),
      deps: deps()
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      maintainers: ["Membrane Team"],
      licenses: ["Apache 2.0"],
      files: ["c_src", "mix.exs", "README*", "LICENSE*", ".formatter.exs", "bundlex.exs"],
      links: %{
        "GitHub" => @github_url,
        "Membrane Framework Homepage" => "https://membraneframework.org"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp deps() do
    [
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
      {:bundlex, "~> 0.2.7"}
    ]
  end
end
