{-# LANGUAGE GeneralizedNewtypeDeriving #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | 'Cql' instances for Spar types, as well as conversion functions used in "Spar.Data"
-- (which does the actual database work).
module Spar.Data.Instances
    (
      -- * Raw database types
      VerdictFormatRow
    , VerdictFormatCon(..)
    , CqlScimUser(..)
      -- ** Conversions
    , fromVerdictFormat
    , toVerdictFormat
    ) where

import Imports
import Cassandra as Cas
import Data.Aeson (FromJSON, ToJSON)
import Data.String.Conversions
import Data.X509 (SignedCertificate)
import SAML2.Util (parseURI')
import Spar.Types
import Text.XML.DSig (renderKeyInfo, parseKeyInfo)
import URI.ByteString

import qualified Data.Aeson as Aeson
import qualified SAML2.WebSSO as SAML
import qualified Web.Scim.Class.User as Scim
import qualified Web.Scim.Schema.User as Scim


instance Cql SAML.XmlText where
    ctype = Tagged TextColumn
    toCql = CqlText . SAML.unsafeFromXmlText

    fromCql (CqlText t) = pure $ SAML.mkXmlText t
    fromCql _           = fail "XmlText: expected CqlText"

instance Cql (SignedCertificate) where
    ctype = Tagged BlobColumn
    toCql = CqlBlob . cs . renderKeyInfo

    fromCql (CqlBlob t) = parseKeyInfo False (cs t)
    fromCql _           = fail "SignedCertificate: expected CqlBlob"

instance Cql (URIRef Absolute) where
    ctype = Tagged TextColumn
    toCql = CqlText . SAML.renderURI

    fromCql (CqlText t) = parseURI' t
    fromCql _           = fail "URI: expected CqlText"

instance Cql SAML.NameID where
    ctype = Tagged TextColumn
    toCql = CqlText . cs . SAML.encodeElem

    fromCql (CqlText t) = SAML.decodeElem (cs t)
    fromCql _           = fail "NameID: expected CqlText"

deriving instance Cql SAML.Issuer
deriving instance Cql SAML.IdPId
deriving instance Cql (SAML.ID SAML.AuthnRequest)

type VerdictFormatRow = (VerdictFormatCon, Maybe URI, Maybe URI)
data VerdictFormatCon = VerdictFormatConWeb | VerdictFormatConMobile

instance Cql VerdictFormatCon where
    ctype = Tagged IntColumn

    toCql VerdictFormatConWeb    = CqlInt 0
    toCql VerdictFormatConMobile = CqlInt 1

    fromCql (CqlInt i) = case i of
        0 -> return VerdictFormatConWeb
        1 -> return VerdictFormatConMobile
        n -> fail $ "unexpected VerdictFormatCon: " ++ show n
    fromCql _ = fail "member-status: int expected"

fromVerdictFormat :: VerdictFormat -> VerdictFormatRow
fromVerdictFormat VerdictFormatWeb                         = (VerdictFormatConWeb, Nothing, Nothing)
fromVerdictFormat (VerdictFormatMobile succredir errredir) = (VerdictFormatConMobile, Just succredir, Just errredir)

toVerdictFormat :: VerdictFormatRow -> Maybe VerdictFormat
toVerdictFormat (VerdictFormatConWeb, Nothing, Nothing)                 = Just VerdictFormatWeb
toVerdictFormat (VerdictFormatConMobile, Just succredir, Just errredir) = Just $ VerdictFormatMobile succredir errredir
toVerdictFormat _                                                       = Nothing

deriving instance Cql ScimToken

-- | Wrapper to work around complications with type synonym family application in the 'Cql'
-- instance.
--
-- Background: 'SparTag' is used to instantiate the open type families in the classes
-- @Scim.UserTypes@, @Scim.GroupTypes@, @Scim.AuthTypes@.  Those type families are not
-- injective, and in general they shouldn't be: it should be possible to map two tags to
-- different user ids, but the same extra user info.  This makes the type of the 'Cql'
-- instance for @'Scim.StoredUser' tag@ undecidable: if the type checker encounters a
-- constraint that gives it the user id and extra info, it can't compute the tag from that to
-- look up the instance.
--
-- Possible solutions:
--
-- * what we're doing here: wrap the type synonyms we can't instantiate into newtypes in the
--   code using hscim.

-- * do not instantiate the type synonym, but its value (in this case
--   @Web.Scim.Schema.Meta.WithMeta (Web.Scim.Schema.Common.WithId (Id U) (Scim.User tag))@
--
-- * Use newtypes instead type in hscim.  This will carry around the tag as a data type rather
--   than applying it, which in turn will enable ghc to type-check instances like @Cql
--   (Scim.StoredUser tag)@.
--
-- * make the type classes parametric in not only the tag, but also all the values of the type
--   families, and add functional dependencies, like this: @class UserInfo tag uid extrainfo |
--   (uid, extrainfo) -> tag, tag -> (uid, extrainfo)@.  this will make writing the instances
--   only a little more awkward, but the rest of the code should change very little, as long
--   as we just apply the type families rather than explicitly imposing the class constraints.
--
-- * given a lot of time: extend ghc with something vaguely similar to @AllowAmbigiousTypes@,
--   where the instance typechecks, and non-injectivity errors are raised when checking the
--   constraint that "calls" the instance.  :)
newtype CqlScimUser tag = CqlScimUser { fromCqlScimUser :: Scim.StoredUser tag }

instance ( Scim.UserTypes tag, uid ~ Scim.UserId tag, extra ~ Scim.UserExtra tag
         , FromJSON extra, ToJSON extra
         , FromJSON uid, ToJSON uid
         ) => Cql (CqlScimUser tag) where
    ctype = Tagged BlobColumn
    toCql = CqlBlob . Aeson.encode . fromCqlScimUser

    fromCql (CqlBlob t) = CqlScimUser <$> Aeson.eitherDecode t
    fromCql _           = fail "Scim.StoredUser: expected CqlBlob"
