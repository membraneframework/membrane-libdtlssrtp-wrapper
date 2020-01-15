# Bunch Native

[![Hex.pm](https://img.shields.io/hexpm/v/bunch_native.svg)](https://hex.pm/packages/bunch_native)
[![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat)](https://hexdocs.pm/bunch_native/)
[![CircleCI](https://circleci.com/gh/membraneframework/bunch-native.svg?style=svg)](https://circleci.com/gh/membraneframework/bunch-native)

Native part of the [Bunch](https://hex.pm/packages/bunch) package.

Documentation is available at [HexDocs](https://hexdocs.pm/bunch_native/).

The source code is available at [GitHub](https://github.com/membraneframework/bunch-native).

## Installation

Add the following line to your `deps` in `mix.exs`. Run `mix deps.get`.

```elixir
{:bunch_native, "~> 0.2.0"}
```

All the native stuff is exported as [Bundlex](https://hex.pm/packages/bundlex) dependencies: `:bunch` and `:bunch_nif` (containing NIF-specific helpers, superset of `:bunch`).
To import, add the following line to your native specification in `bundlex.exs`:
```elixir
deps: [bunch_native: :bunch] # or :bunch_nif
```
and another one in your native header file:
```c
#import <bunch/bunch.h> // or bunch_nif.h
```

## Copyright and License

Copyright 2018, [Software Mansion](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=membrane)

[![Software Mansion](https://membraneframework.github.io/static/logo/swm_logo_readme.png)](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=membrane)

Licensed under the [Apache License, Version 2.0](LICENSE)
