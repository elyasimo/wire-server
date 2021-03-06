module Main (main) where

import Imports
import CargoHold.Run (run)
import OpenSSL (withOpenSSL)

import Util.Options

main :: IO ()
main = withOpenSSL $ do
    options <- getOptions desc Nothing defaultPath
    run options
  where
    desc = "Cargohold - Asset Storage"
    defaultPath = "/etc/wire/cargohold/conf/cargohold.yaml"
