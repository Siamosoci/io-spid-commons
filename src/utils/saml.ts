/**
 * Methods used to tamper passport-saml generated SAML XML.
 *
 * SPID protocol has some peculiarities that need to be addressed
 * to make request, metadata and responses compliant.
 */
// tslint:disable-next-line: no-submodule-imports
import { UTCISODateFromString } from "@pagopa/ts-commons/lib/dates";
// tslint:disable-next-line: no-submodule-imports
import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { predicate as PR } from "fp-ts";
import { difference } from "fp-ts/lib/Array";
import * as E from "fp-ts/lib/Either";
import { not, pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/lib/Option";
import { Eq } from "fp-ts/lib/string";
import * as TE from "fp-ts/lib/TaskEither";
import { TaskEither } from "fp-ts/lib/TaskEither";
import { DOMParser, XMLSerializer } from "xmldom";
import { SPID_LEVELS, SPID_USER_ATTRIBUTES } from "../config";
import { EventTracker } from "../index";
import { PreValidateResponseT } from "../strategy/spid";
import { StrictResponseValidationOptions } from "./middleware";
import {
// <<<<<<< HEAD
//   ContactType,
//   EntityType,
//   getSpidStrategyOption,
//   IServiceProviderConfig,
//   ISpidStrategyOptions,
//   StrictResponseValidationOptions
// } from "./middleware";
// import { fromArray } from "fp-ts/lib/NonEmptyArray2v";

// export type SamlAttributeT = keyof typeof SPID_USER_ATTRIBUTES;

// interface IEntrypointCerts {
//   // tslint:disable-next-line: readonly-array
//   cert: NonEmptyString[];
//   entryPoint?: string;
//   idpIssuer?: string;
// }

// export const SAML_NAMESPACE = {
//   ASSERTION: "urn:oasis:names:tc:SAML:2.0:assertion",
//   PROTOCOL: "urn:oasis:names:tc:SAML:2.0:protocol",
//   SPID: "https://spid.gov.it/saml-extensions",
//   XMLDSIG: "http://www.w3.org/2000/09/xmldsig#"
// };

// const ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

// const decodeBase64 = (s: string) => Buffer.from(s, "base64").toString("utf8");

// /**
//  * Remove prefix and suffix from x509 certificate.
//  */
// const cleanCert = (cert: string) =>
//   cert
//     .replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "")
//     .replace(/-+END CERTIFICATE-+\r?\n?/, "")
//     .replace(/\r\n/g, "\n");

// const SAMLResponse = t.type({
//   SAMLResponse: t.string
// });

// /**
//  * True if the element contains at least one element signed using hamc
//  * @param e
//  */
// const isSignedWithHmac = (e: Element): boolean => {
//   const signatures = e.getElementsByTagNameNS(
//     SAML_NAMESPACE.XMLDSIG,
//     "SignatureMethod"
//   );
//   return Array.from({ length: signatures.length })
//     .map((_, i) => signatures.item(i))
//     .some(
//       item =>
//         item?.getAttribute("Algorithm")?.valueOf() ===
//         "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
//     );
// };

// const notSignedWithHmacPredicate = fromPredicate(
//   not(isSignedWithHmac),
//   _ => new Error("HMAC Signature is forbidden")
// );

// export const getXmlFromSamlResponse = (body: unknown): Option<Document> =>
//   fromEither(SAMLResponse.decode(body))
//     .map(_ => decodeBase64(_.SAMLResponse))
//     .chain(_ => optionTryCatch(() => new DOMParser().parseFromString(_)));

// /**
//  * Extract StatusMessage from SAML response
//  *
//  * ie. for <StatusMessage>ErrorCode nr22</StatusMessage>
//  * returns "22"
//  */
// export function getErrorCodeFromResponse(doc: Document): Option<string> {
//   return fromNullable(
//     doc.getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "StatusMessage")
//   )
//     .chain(responseStatusMessageEl => {
//       return responseStatusMessageEl &&
//         responseStatusMessageEl[0] &&
//         responseStatusMessageEl[0].textContent
//         ? some(responseStatusMessageEl[0].textContent.trim())
//         : none;
//     })
//     .chain(errorString => {
//       const indexString = "ErrorCode nr";
//       const errorCode = errorString.slice(
//         errorString.indexOf(indexString) + indexString.length
//       );
//       return errorCode !== "" ? some(errorCode) : none;
//     });
// }

// /**
//  * Extracts the issuer field from the response body.
//  */
// export const getSamlIssuer = (doc: Document): Option<string> => {
//   return fromNullable(
//     doc.getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer").item(0)
//   ).mapNullable(_ => _.textContent?.trim());
// };

// /**
//  * Extracts IDP entityID from query parameter (if any).
//  *
//  * @returns
//  *  - the certificates (and entrypoint) for the IDP that matches the provided entityID
//  *  - all IDP certificates if no entityID is provided (and no entrypoint)
//  *  - none if no IDP matches the provided entityID
//  */
// const getEntrypointCerts = (
//   req: ExpressRequest,
//   idps: ISpidStrategyOptions["idp"]
// ): Option<IEntrypointCerts> => {
//   return fromNullable(req)
//     .mapNullable(r => r.query)
//     .mapNullable(q => q.entityID)
//     .chain(entityID =>
//       // As only strings can be key of an object (other than number and Symbol),
//       //  we have to narrow type to have the compiler accept it
//       // In the unlikely case entityID is not a string, an empty value is returned
//       typeof entityID === "string"
//         ? fromNullable(idps[entityID]).map(
//             (idp): IEntrypointCerts => ({
//               cert: idp.cert.toArray(),
//               entryPoint: idp.entryPoint,
//               idpIssuer: idp.entityID
//             })
//           )
//         : none
//     )
//     .alt(
//       // collect all IDP certificates in case no entityID is provided
//       some({
//         cert: flatten(
//           collect(idps, (_, idp) => (idp && idp.cert ? idp.cert.toArray() : []))
//         ),
//         // TODO: leave entryPoint undefined when this gets fixed
//         // @see https://github.com/bergie/passport-saml/issues/415
//         entryPoint: ""
//       } as IEntrypointCerts)
//     );
// };

// export const getIDFromRequest = (requestXML: string): Option<string> => {
//   const xmlRequest = new DOMParser().parseFromString(requestXML, "text/xml");
//   return fromNullable(
//     xmlRequest
//       .getElementsByTagNameNS(SAML_NAMESPACE.PROTOCOL, "AuthnRequest")
//       .item(0)
//   ).chain(AuthnRequest =>
//     fromEither(NonEmptyString.decode(AuthnRequest.getAttribute("ID")))
//   );
// };

// const getAuthnContextValueFromResponse = (response: string): Option<string> => {
//   const xmlResponse = new DOMParser().parseFromString(response, "text/xml");
//   // ie. <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
//   const responseAuthLevelEl = xmlResponse.getElementsByTagNameNS(
//     SAML_NAMESPACE.ASSERTION,
//     "AuthnContextClassRef"
//   );
//   return responseAuthLevelEl[0] && responseAuthLevelEl[0].textContent
//     ? some(responseAuthLevelEl[0].textContent.trim())
//     : none;
// };

// /**
//  * Extracts the correct SPID level from response.
//  */
// const getAuthSalmOptions = (
//   req: ExpressRequest,
//   decodedResponse?: string
// ): Option<Partial<SamlConfig>> => {
//   return (
//     fromNullable(req)
//       .mapNullable(r => r.query)
//       .mapNullable(q => q.authLevel)
//       // As only strings can be key of SPID_LEVELS record,
//       //  we have to narrow type to have the compiler accept it
//       // In the unlikely case authLevel is not a string, an empty value is returned
//       .filter((e): e is string => typeof e === "string")
//       .chain(authLevel =>
//         lookup(authLevel, SPID_LEVELS)
//           .map(authnContext => ({
//             authnContext,
//             forceAuthn: authLevel !== "SpidL1"
//           }))
//           .orElse(() => {
//             logger.error(
//               "SPID cannot find a valid authnContext for given authLevel: %s",
//               authLevel
//             );
//             return none;
//           })
//       )
//       .alt(
//         fromNullable(decodedResponse)
//           .chain(response => getAuthnContextValueFromResponse(response))
//           .chain(authnContext =>
//             lookup(authnContext, SPID_URLS)
//               // check if the parsed value is a valid SPID AuthLevel
//               .map(authLevel => {
//                 return {
//                   authnContext,
//                   forceAuthn: authLevel !== "SpidL1"
//                 };
//               })
//               .orElse(() => {
//                 logger.error(
//                   "SPID cannot find a valid authLevel for given authnContext: %s",
//                   authnContext
//                 );
//                 return none;
//               })
//           )
//       )
//   );
// };

// /**
//  * Reads dates information in x509 certificate
//  * and logs remaining time to its expiration date.
//  *
//  * @param samlCert x509 certificate as string
//  */
// export function logSamlCertExpiration(samlCert: string): void {
//   try {
//     const out = pki.certificateFromPem(samlCert);
//     if (out.validity.notAfter) {
//       const timeDiff = distanceInWordsToNow(out.validity.notAfter);
//       const warningDate = subDays(new Date(), 60);
//       if (isAfter(out.validity.notAfter, warningDate)) {
//         logger.info("samlCert expire in %s", timeDiff);
//       } else if (isAfter(out.validity.notAfter, new Date())) {
//         logger.warn("samlCert expire in %s", timeDiff);
//       } else {
//         logger.error("samlCert expired from %s", timeDiff);
//       }
//     } else {
//       logger.error("Missing expiration date on saml certificate.");
//     }
//   } catch (e) {
//     logger.error("Error calculating saml cert expiration: %s", e);
//   }
// }

// /**
//  * This method extracts the correct IDP metadata
//  * from the passport strategy options.
//  *
//  * It's executed for every SPID login (when passport
//  * middleware is configured) and when generating
//  * the Service Provider metadata.
//  */
// export const getSamlOptions: MultiSamlConfig["getSamlOptions"] = (
//   req,
//   done
// ) => {
//   try {
//     // Get decoded response
//     const decodedResponse =
//       req.body && req.body.SAMLResponse
//         ? decodeBase64(req.body.SAMLResponse)
//         : undefined;

//     // Get SPID strategy options with IDPs metadata
//     const maybeSpidStrategyOptions = fromNullable(
//       getSpidStrategyOption(req.app)
//     );
//     if (isNone(maybeSpidStrategyOptions)) {
//       throw new Error(
//         "Missing Spid Strategy Option configuration inside express App"
//       );
//     }

//     // Get the correct entry within the IDP metadata object
//     const maybeEntrypointCerts = maybeSpidStrategyOptions.chain(
//       spidStrategyOptions => getEntrypointCerts(req, spidStrategyOptions.idp)
//     );
//     if (isNone(maybeEntrypointCerts)) {
//       logger.debug(
//         `SPID cannot find a valid idp in spidOptions for given entityID: ${req.query.entityID}`
//       );
//     }
//     const entrypointCerts = maybeEntrypointCerts.getOrElse(
//       {} as IEntrypointCerts
//     );

//     // Get authnContext (SPID level) and forceAuthn from request payload
//     const maybeAuthOptions = getAuthSalmOptions(req, decodedResponse);
//     if (isNone(maybeAuthOptions)) {
//       logger.debug(
//         "SPID cannot find authnContext in response %s",
//         decodedResponse
//       );
//     }
//     const authOptions = maybeAuthOptions.getOrElse({});
//     const options = {
//       ...maybeSpidStrategyOptions.value.sp,
//       ...authOptions,
//       ...entrypointCerts
//     };
//     return done(null, options);
//   } catch (e) {
//     return done(e);
//   }
// };

// //
// //  Service Provider Metadata
// //

// const getSpidAttributesMetadata = (
//   serviceProviderConfig: IServiceProviderConfig
// ) => {
//   return serviceProviderConfig.requiredAttributes
//     ? serviceProviderConfig.requiredAttributes.attributes.map(item => ({
//         $: {
//           FriendlyName: SPID_USER_ATTRIBUTES[item] || "",
//           Name: item,
//           NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
//         }
//       }))
//     : [];
// };

// const getSpidOrganizationMetadata = (
//   serviceProviderConfig: IServiceProviderConfig
// ) => {
//   return serviceProviderConfig.organization
//     ? {
//         Organization: {
//           OrganizationName: {
//             $: { "xml:lang": "it" },
//             _: serviceProviderConfig.organization.name
//           },
//           // must appear after organization name
//           // tslint:disable-next-line: object-literal-sort-keys
//           OrganizationDisplayName: {
//             $: { "xml:lang": "it" },
//             _: serviceProviderConfig.organization.displayName
//           },
//           OrganizationURL: {
//             $: { "xml:lang": "it" },
//             _: serviceProviderConfig.organization.URL
//           }
//         }
//       }
//     : {};
// };

// const getSpidContactPersonMetadata = (
//   serviceProviderConfig: IServiceProviderConfig
// ) => {
//   return serviceProviderConfig.contacts
//     ? serviceProviderConfig.contacts
//         .map(item => {
//           const contact = {
//             $: {
//               contactType: item.contactType
//             },
//             Company: item.company,
//             EmailAddress: item.email,
//             ...(item.phone ? { TelephoneNumber: item.phone } : {})
//           };
//           if (item.contactType === ContactType.OTHER) {
//             return {
//               Extensions: {
//                 ...(item.extensions.IPACode
//                   ? { "spid:IPACode": item.extensions.IPACode }
//                   : {}),
//                 ...(item.extensions.VATNumber
//                   ? { "spid:VATNumber": item.extensions.VATNumber }
//                   : {}),
//                 ...(item.extensions?.FiscalCode
//                   ? { "spid:FiscalCode": item.extensions.FiscalCode }
//                   : {}),
//                 ...(item.entityType === EntityType.AGGREGATOR
//                   ? { [`spid:${item.extensions.aggregatorType}`]: {} }
//                   : {}),
//                 ...(item.entityType === EntityType.AGGREGATED
//                   ? { [`spid:Private`]: {} }
//                   : {})
//               },
//               ...contact,
//               $: {
//                 ...contact.$,
//                 "spid:entityType": item.entityType === EntityType.AGGREGATOR ? item.entityType : undefined
//               }
//             };
//           } else if (item.contactType === ContactType.BILLING) {
//             const datiAnagrafici = item.extensions.cessionarioCommittente.datiAnagrafici;
//             const sede = item.extensions.cessionarioCommittente.sede;
//             return {
//               "Extensions": {
//                 "fpa:CessionarioCommittente": {
//                   "fpa:DatiAnagrafici": {
//                     "fpa:IdFiscaleIVA": {
//                       "fpa:IdPaese": datiAnagrafici.idFiscaleIVA.idPaese,
//                       "fpa:IdCodice": datiAnagrafici.idFiscaleIVA.idCodice
//                     },
//                     "fpa:Anagrafica": {
//                       "fpa:Denominazione": datiAnagrafici.anagrafica.denominazione
//                     }
//                   },
//                   "fpa:Sede": {
//                     "fpa:Indirizzo": sede.indirizzo,
//                     "fpa:NumeroCivico": sede.numeroCivico,
//                     "fpa:CAP": sede.CAP,
//                     "fpa:Comune": sede.comune,
//                     "fpa:Provincia": sede.provincia,
//                     "fpa:Nazione": sede.nazione
//                   }
//                 },
//                 $: {
//                   "xmlns:fpa": "https://spid.gov.it/invoicing-extensions"
//                 },
//               },
//               ...contact,
//               $: {
//                 ...contact.$,
//               }
//             }
//           }
//           return contact;
//         })
//         // Contacts array is limited to 3 elements
//         .slice(0, 3)
//     : {};
// };

// const getKeyInfoForMetadata = (publicCert: string, privateKey: string) => ({
//   file: privateKey,
//   getKey: () => Buffer.from(privateKey),
//   getKeyInfo: () =>
//     `<X509Data><X509Certificate>${publicCert}</X509Certificate></X509Data>`
// });

// export const getMetadataTamperer = (
//   xmlBuilder: Builder,
//   serviceProviderConfig: IServiceProviderConfig,
//   samlConfig: SamlConfig
// ) => (generateXml: string): TaskEither<Error, string> => {
//   return tryCatch(() => parseStringPromise(generateXml), toError)
//     .chain(o =>
//       tryCatch(async () => {
//         // it is safe to mutate object here since it is
//         // deserialized and serialized locally in this method
//         const sso = o.EntityDescriptor.SPSSODescriptor[0];
//         // tslint:disable-next-line: no-object-mutation
//         sso.$ = {
//           ...sso.$,
//           AuthnRequestsSigned: true,
//           WantAssertionsSigned: true
//         };
//         // tslint:disable-next-line: no-object-mutation
//         sso.AssertionConsumerService[0].$.index = 0;
//         // tslint:disable-next-line: no-object-mutation
//         sso.AttributeConsumingService = {
//           $: {
//             index: samlConfig.attributeConsumingServiceIndex
//           },
//           ServiceName: {
//             $: {
//               "xml:lang": "it"
//             },
//             _: serviceProviderConfig.requiredAttributes.name
//           },
//           // must appear after attributes
//           // tslint:disable-next-line: object-literal-sort-keys
//           RequestedAttribute: getSpidAttributesMetadata(serviceProviderConfig)
//         };
//         // tslint:disable-next-line: no-object-mutation
//         o.EntityDescriptor = {
//           ...o.EntityDescriptor,
//           ...getSpidOrganizationMetadata(serviceProviderConfig)
//         };
//         if (serviceProviderConfig.contacts) {
//           // tslint:disable-next-line: no-object-mutation
//           o.EntityDescriptor = {
//             ...o.EntityDescriptor,
//             $: {
//               ...o.EntityDescriptor.$,
//               "xmlns:spid": SAML_NAMESPACE.SPID
//             },
//             // tslint:disable-next-line: no-inferred-empty-object-type
//             ContactPerson: getSpidContactPersonMetadata(serviceProviderConfig)
//           };
//         }
//         return o;
//       }, toError)
//     )
//     .chain(_ => tryCatch(async () => xmlBuilder.buildObject(_), toError))
//     .chain(xml =>
//       tryCatch(async () => {
//         // sign xml metadata
//         if (!samlConfig.privateCert) {
//           throw new Error(
//             "You must provide a private key to sign SPID service provider metadata."
//           );
//         }
//         const sig = new xmlCrypto.SignedXml();
//         const publicCert = cleanCert(serviceProviderConfig.publicCert);
//         // tslint:disable-next-line: no-object-mutation
//         sig.keyInfoProvider = getKeyInfoForMetadata(
//           publicCert,
//           samlConfig.privateCert
//         );
//         // tslint:disable-next-line: no-object-mutation
//         sig.signatureAlgorithm =
//           "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
//         // tslint:disable-next-line: no-object-mutation
//         sig.signingKey = samlConfig.privateCert;
//         sig.addReference(
//           "//*[local-name(.)='EntityDescriptor']",
//           [
//             "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
//             "http://www.w3.org/2001/10/xml-exc-c14n#"
//           ],
//           "http://www.w3.org/2001/04/xmlenc#sha256"
//         );
//         sig.computeSignature(xml, {
//           // Place the signature tag before all other tags
//           location: { reference: "", action: "prepend" }
//         });
//         return sig.getSignedXml();
//       }, toError)
//     );
// };

// //
// //  Authorize request
// //

// export const getAuthorizeRequestTamperer = (
//   xmlBuilder: Builder,
//   _: IServiceProviderConfig,
//   samlConfig: SamlConfig
// ) => (generateXml: string): TaskEither<Error, string> => {
//   return tryCatch(() => parseStringPromise(generateXml), toError)
//     .chain(o =>
//       tryCatch(async () => {
//         // it is safe to mutate object here since it is
//         // deserialized and serialized locally in this method
//         // tslint:disable-next-line: no-any
//         const authnRequest = o["samlp:AuthnRequest"];
//         // tslint:disable-next-line: no-object-mutation no-delete
//         delete authnRequest["samlp:NameIDPolicy"][0].$.AllowCreate;
//         // tslint:disable-next-line: no-object-mutation
//         authnRequest["saml:Issuer"][0].$.NameQualifier = samlConfig.issuer;
//         // tslint:disable-next-line: no-object-mutation
//         authnRequest["saml:Issuer"][0].$.Format = ISSUER_FORMAT;
//         return o;
//       }, toError)
//     )
//     .chain(obj => tryCatch(async () => xmlBuilder.buildObject(obj), toError));
// };

// //
// //  Validate response
// //

// const utcStringToDate = (value: string, tag: string): Either<Error, Date> =>
//   UTCISODateFromString.decode(value).mapLeft(
//     () => new Error(`${tag} must be an UTCISO format date string`)
//   );

// const validateIssuer = (
//   fatherElement: Element,
//   idpIssuer: string
// ): Either<Error, Element> =>
//   fromOption(new Error("Issuer element must be present"))(
//     fromArray(
//       Array.from(
//         fatherElement
//           .getElementsByTagNameNS(SAML_NAMESPACE.ASSERTION, "Issuer")
//       )
//     )
//   ).chain(Issuers => // Issuer must be a direct child of fatherElement
//     fromOption(new Error("Issuer element must be present"))(
//       fromNullable(
//         Issuers.find(Issuer =>
//           Issuer.parentNode === fatherElement
//         )
//       )
//     )
//   ).chain(Issuer =>
//     NonEmptyString.decode(Issuer.textContent?.trim())
//       .mapLeft(() => new Error("Issuer element must be not empty"))
//       .chain(
//         fromPredicate(
//           IssuerTextContent => {
//             return IssuerTextContent === idpIssuer;
//           },
//           () => new Error(`Invalid Issuer. Expected value is ${idpIssuer}`)
//         )
//       )
//       .map(() => Issuer)
//   );

// const mainAttributeValidation = (
//   requestOrAssertion: Element,
//   acceptedClockSkewMs: number = 0
// ): Either<Error, Date> => {
//   return NonEmptyString.decode(requestOrAssertion.getAttribute("ID"))
//     .mapLeft(() => new Error("Assertion must contain a non empty ID"))
//     .map(() => requestOrAssertion.getAttribute("Version"))
//     .chain(
//       fromPredicate(
//         Version => Version === "2.0",
//         () => new Error("Version version must be 2.0")
//       )
//     )
//     .chain(() =>
//       fromOption(new Error("Assertion must contain a non empty IssueInstant"))(
//         fromNullable(requestOrAssertion.getAttribute("IssueInstant"))
//       )
//     )
//     .chain(IssueInstant => utcStringToDate(IssueInstant, "IssueInstant"))
//     .chain(
//       fromPredicate(
//         _ =>
//           _.getTime() <
//           (acceptedClockSkewMs === -1
//             ? Infinity
//             : Date.now() + acceptedClockSkewMs),
//         () => new Error("IssueInstant must be in the past")
//       )
//     );
// };

// const isEmptyNode = (element: Element): boolean => {
//   if (element.childNodes.length > 1) {
//     return false;
//   } else if (
//     element.firstChild &&
//     element.firstChild.nodeType === element.ELEMENT_NODE
//   ) {
//     return false;
//   } else if (
//     element.textContent &&
//     element.textContent.replace(/[\r\n\ ]+/g, "") !== ""
//   ) {
//     return false;
//   }
//   return true;
// };

// const isOverflowNumberOf = (
//   elemArray: readonly Element[],
//   maxNumberOfChildren: number
// ): boolean =>
//   elemArray.filter(e => e.nodeType === e.ELEMENT_NODE).length >
//   maxNumberOfChildren;

// export const TransformError = t.interface({
//   idpIssuer: t.string,
//   message: t.string,
//   numberOfTransforms: t.number
// });
// export type TransformError = t.TypeOf<typeof TransformError>;

// const transformsValidation = (
//   targetElement: Element,
//   idpIssuer: string
// ): Either<TransformError, Element> => {
//   return fromPredicateOption(
//     (elements: readonly Element[]) => elements.length > 0
//   )(
//     Array.from(
//       targetElement.getElementsByTagNameNS(SAML_NAMESPACE.XMLDSIG, "Transform")
//     )
//   ).foldL(
//     () => right(targetElement),
//     transformElements =>
//       fromPredicate(
//         (_: readonly Element[]) => !isOverflowNumberOf(_, 4),
//         _ =>
//           TransformError.encode({
//             idpIssuer,
//             message: "Transform element cannot occurs more than 4 times",
//             numberOfTransforms: _.length
//           })
//       )(transformElements).map(() => targetElement)
//   );
// };

// const notOnOrAfterValidation = (
//   element: Element,
//   acceptedClockSkewMs: number = 0
// ) => {
//   return NonEmptyString.decode(element.getAttribute("NotOnOrAfter"))
//     .mapLeft(
//       () => new Error("NotOnOrAfter attribute must be a non empty string")
//     )
//     .chain(NotOnOrAfter => utcStringToDate(NotOnOrAfter, "NotOnOrAfter"))
//     .chain(
//       fromPredicate(
//         NotOnOrAfter =>
//           NotOnOrAfter.getTime() >
//           (acceptedClockSkewMs === -1
//             ? -Infinity
//             : Date.now() - acceptedClockSkewMs),
//         () => new Error("NotOnOrAfter must be in the future")
//       )
//     );
// =======
  assertionValidation,
  ISSUER_FORMAT,
  notSignedWithHmacPredicate,
  TransformError,
  transformsValidation,
  validateIssuer
} from "./samlUtils";
import {
  getAuthorizeRequestTamperer,
  getErrorCodeFromResponse,
  getIDFromRequest,
  getMetadataTamperer,
  getSamlIssuer,
  getSamlOptions,
  getXmlFromSamlResponse,
  isEmptyNode,
  logSamlCertExpiration,
  mainAttributeValidation,
  SAML_NAMESPACE
} from "./samlUtils";

export {
  SAML_NAMESPACE,
  logSamlCertExpiration,
  getIDFromRequest,
  getMetadataTamperer,
  getXmlFromSamlResponse,
  getSamlOptions,
  getErrorCodeFromResponse,
  getAuthorizeRequestTamperer,
  getSamlIssuer,
  TransformError
};

export type SamlAttributeT = keyof typeof SPID_USER_ATTRIBUTES;

export const getPreValidateResponse = (
  strictValidationOptions?: StrictResponseValidationOptions,
  eventHandler?: EventTracker
  // tslint:disable-next-line: no-big-function
): PreValidateResponseT => (
  samlConfig,
  body,
  extendedCacheProvider,
  doneCb,
  callback
  // tslint:disable-next-line: no-big-function
) => {
  const maybeDoc = getXmlFromSamlResponse(body);

  if (O.isNone(maybeDoc)) {
    throw new Error("Empty SAML response");
  }
  const doc = maybeDoc.value;

  const responsesCollection = doc.getElementsByTagNameNS(
    SAML_NAMESPACE.PROTOCOL,
    "Response"
  );

  const hasStrictValidation = pipe(
    O.fromNullable(strictValidationOptions),
    O.chain(_ =>
      pipe(
        getSamlIssuer(doc),
        O.chainNullableK(issuer => _[issuer])
      )
    ),
    O.getOrElse(() => false)
  );

  interface IBaseOutput {
    InResponseTo: NonEmptyString;
    Assertion: Element;
    IssueInstant: Date;
    Response: Element;
    AssertionIssueInstant: Date;
  }

  interface ISamlCacheType {
    RequestXML: string;
    createdAt: Date;
    idpIssuer: string;
  }

  type IRequestAndResponseStep = IBaseOutput & {
    SAMLRequestCache: ISamlCacheType;
  };

  type ISAMLRequest = IRequestAndResponseStep & { Request: Document };

  type IIssueInstant = ISAMLRequest & {
    RequestIssueInstant: Date;
    RequestAuthnRequest: Element;
  };

  type IIssueInstantWithAuthnContextCR = IIssueInstant & {
    RequestAuthnContextClassRef: NonEmptyString;
  };

  interface ITransformValidation {
    idpIssuer: string;
    message: string;
    numberOfTransforms: number;
  }

  const responseElementValidationStep: TaskEither<
    Error,
    IBaseOutput
  > = TE.fromEither(
    pipe(
      responsesCollection,
      E.fromPredicate(
        _ => _.length < 2,
        _ => new Error("SAML Response must have only one Response element")
      ),
      E.map(_ => _.item(0)),
      E.chain(Response =>
        E.fromOption(
          () => new Error("Missing Reponse element inside SAML Response")
        )(O.fromNullable(Response))
      ),
      E.chain(Response =>
        pipe(
          mainAttributeValidation(Response, samlConfig.acceptedClockSkewMs),
          E.map(IssueInstant => ({
            IssueInstant,
            Response
          }))
        )
      ),
      E.chain(_ =>
        pipe(
          NonEmptyString.decode(_.Response.getAttribute("Destination")),
          E.mapLeft(
            () => new Error("Response must contain a non empty Destination")
          ),
          E.chain(
            E.fromPredicate(
              Destination => Destination === samlConfig.callbackUrl,
              () =>
                new Error(
                  "Destination must be equal to AssertionConsumerServiceURL"
                )
            )
          ),
          E.map(() => _)
        )
      ),
      E.chain(_ =>
        pipe(
          E.fromOption(() => new Error("Status element must be present"))(
            O.fromNullable(
              _.Response.getElementsByTagNameNS(
                SAML_NAMESPACE.PROTOCOL,
                "Status"
              ).item(0)
            )
          ),
          E.mapLeft(
            () => new Error("Status element must be present into Response")
          ),
          E.chain(
            E.fromPredicate(
              not(isEmptyNode),
              () => new Error("Status element must be present not empty")
            )
          ),
          E.chain(Status =>
            E.fromOption(() => new Error("StatusCode element must be present"))(
              O.fromNullable(
                Status.getElementsByTagNameNS(
                  SAML_NAMESPACE.PROTOCOL,
                  "StatusCode"
                ).item(0)
              )
            )
          ),
          E.chain(StatusCode =>
            pipe(
              E.fromOption(
                () => new Error("StatusCode must contain a non empty Value")
              )(O.fromNullable(StatusCode.getAttribute("Value"))),
              E.chain(statusCode => {
                // TODO: Must show an error page to the user (26)
                return pipe(
                  statusCode,
                  E.fromPredicate(
                    Value =>
                      Value.toLowerCase() ===
                      "urn:oasis:names:tc:SAML:2.0:status:Success".toLowerCase(),
                    () =>
                      new Error(
                        `Value attribute of StatusCode is invalid: ${statusCode}`
                      )
                  )
                );
              }),
              E.map(() => _)
            )
          )
        )
      ),
      E.chain(
        E.fromPredicate(
          predicate =>
            predicate.Response.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "EncryptedAssertion"
            ).length === 0,
          _ => new Error("EncryptedAssertion element is forbidden")
        )
      ),
      E.chain(p =>
        pipe(
          notSignedWithHmacPredicate(p.Response),
          E.map(_ => p)
        )
      ),
      E.chain(
        E.fromPredicate(
          predicate =>
            predicate.Response.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "Assertion"
            ).length < 2,
          _ => new Error("SAML Response must have only one Assertion element")
        )
      ),
      E.chain(_ =>
        pipe(
          E.fromOption(() => new Error("Assertion element must be present"))(
            O.fromNullable(
              _.Response.getElementsByTagNameNS(
                SAML_NAMESPACE.ASSERTION,
                "Assertion"
              ).item(0)
            )
          ),
          E.map(assertion => ({ ..._, Assertion: assertion }))
        )
      ),
      E.chain(_ =>
        pipe(
          NonEmptyString.decode(_.Response.getAttribute("InResponseTo")),
          E.mapLeft(
            () => new Error("InResponseTo must contain a non empty string")
          ),
          E.map(inResponseTo => ({ ..._, InResponseTo: inResponseTo }))
        )
      ),
      E.chain(_ =>
        pipe(
          mainAttributeValidation(_.Assertion, samlConfig.acceptedClockSkewMs),
          E.map(IssueInstant => ({
            AssertionIssueInstant: IssueInstant,
            ..._
          }))
        )
      )
    )
  );

  const returnRequestAndResponseStep = (
    _: IBaseOutput
  ): TaskEither<Error, IRequestAndResponseStep> =>
    pipe(
      extendedCacheProvider.get(_.InResponseTo),
      TE.map(SAMLRequestCache => ({ ..._, SAMLRequestCache })),
      TE.map(
        __ => (
          doneCb &&
            O.tryCatch(() =>
              doneCb(
                __.SAMLRequestCache.RequestXML,
                new XMLSerializer().serializeToString(doc)
              )
            ),
          __
        )
      )
    );

  const parseSAMLRequestStep = (
    _: IRequestAndResponseStep
  ): TaskEither<Error, ISAMLRequest> =>
    pipe(
      TE.fromEither(
        E.fromOption(
          () => new Error("An error occurs parsing the cached SAML Request")
        )(
          O.tryCatch(() =>
            new DOMParser().parseFromString(_.SAMLRequestCache.RequestXML)
          )
        )
      ),
      TE.map(Request => ({ ..._, Request }))
    );

  const getIssueInstantFromRequestStep = (
    _: ISAMLRequest
  ): TaskEither<Error, IIssueInstant> =>
    pipe(
      TE.fromEither(
        E.fromOption(
          () => new Error("Missing AuthnRequest into Cached Request")
        )(
          O.fromNullable(
            _.Request.getElementsByTagNameNS(
              SAML_NAMESPACE.PROTOCOL,
              "AuthnRequest"
            ).item(0)
          )
        )
      ),
      TE.map(RequestAuthnRequest => ({ ..._, RequestAuthnRequest })),
      TE.chain(__ =>
        pipe(
          TE.fromEither(
            pipe(
              UTCISODateFromString.decode(
                __.RequestAuthnRequest.getAttribute("IssueInstant")
              ),
              E.mapLeft(
                () =>
                  new Error(
                    "IssueInstant into the Request must be a valid UTC string"
                  )
              )
            )
          ),
          TE.map(RequestIssueInstant => ({ ...__, RequestIssueInstant }))
        )
      )
    );

  const issueInstantValidationStep = (
    _: IIssueInstant
  ): TaskEither<Error, IIssueInstant> =>
    pipe(
      TE.fromEither(
        pipe(
          _.RequestIssueInstant,
          E.fromPredicate(
            _1 => _1.getTime() <= _.IssueInstant.getTime(),
            () =>
              new Error("Response IssueInstant must after Request IssueInstant")
          )
        )
      ),
      TE.map(() => _)
    );

  const assertionIssueInstantValidationStep = (
    _: IIssueInstant
  ): TaskEither<Error, IIssueInstant> =>
    pipe(
      TE.fromEither(
        pipe(
          _.RequestIssueInstant,
          E.fromPredicate(
            _1 => _1.getTime() <= _.AssertionIssueInstant.getTime(),
            () =>
              new Error(
                "Assertion IssueInstant must after Request IssueInstant"
              )
          )
        )
      ),
      TE.map(() => _)
    );

  const authnContextClassRefValidationStep = (
    _: IIssueInstant
  ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
    TE.fromEither(
      pipe(
        E.fromOption(
          () =>
            new Error(
              "Missing AuthnContextClassRef inside cached SAML Response"
            )
        )(
          O.fromNullable(
            _.RequestAuthnRequest.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "AuthnContextClassRef"
            ).item(0)
          )
        ),
        E.chain(
          E.fromPredicate(
            PR.not(isEmptyNode),
            () => new Error("Subject element must be not empty")
          )
        ),
        E.chain(RequestAuthnContextClassRef =>
          pipe(
            NonEmptyString.decode(
              RequestAuthnContextClassRef.textContent?.trim()
            ),
            E.mapLeft(
              () =>
                new Error(
                  "AuthnContextClassRef inside cached Request must be a non empty string"
                )
            )
          )
        ),
        E.chain(
          E.fromPredicate(
            reqAuthnContextClassRef =>
              reqAuthnContextClassRef === SPID_LEVELS.SpidL1 ||
              reqAuthnContextClassRef === SPID_LEVELS.SpidL2 ||
              reqAuthnContextClassRef === SPID_LEVELS.SpidL3,
            () => new Error("Unexpected Request authnContextClassRef value")
          )
        ),
        E.map(rACCR => ({
          ..._,
          RequestAuthnContextClassRef: rACCR
        }))
      )
    );

  const attributesValidationStep = (
    _: IIssueInstantWithAuthnContextCR
  ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
    pipe(
      TE.fromEither(
        assertionValidation(
          _.Assertion,
          samlConfig,
          _.InResponseTo,
          _.RequestAuthnContextClassRef
        )
      ),
      TE.chain(Attributes => {
        if (!hasStrictValidation) {
          // Skip Attribute validation if IDP has non-strict validation option
          return TE.right(Attributes);
        }
        const missingAttributes = difference(Eq)(
          // tslint:disable-next-line: no-any
          (samlConfig as any).attributes?.attributes?.attributes || [
            "Request attributes must be defined"
          ],
          Array.from(Attributes).reduce((prev, attr) => {
            const attribute = attr.getAttribute("Name");
            if (attribute) {
              return [...prev, attribute];
            }
            return prev;
          }, new Array<string>())
        );
        return TE.fromEither(
          E.fromPredicate(
            () => missingAttributes.length === 0,
            () =>
              new Error(
                `Missing required Attributes: ${missingAttributes.toString()}`
              )
          )(Attributes)
        );
      }),
      TE.map(() => _)
    );

  const responseIssuerValidationStep = (
    _: IIssueInstantWithAuthnContextCR
  ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
    pipe(
      TE.fromEither(
        pipe(
          validateIssuer(_.Response, _.SAMLRequestCache.idpIssuer),
          E.chainW(Issuer =>
            pipe(
              E.fromOption(() => "Format missing")(
                O.fromNullable(Issuer.getAttribute("Format"))
              ),
              E.mapLeft(() => E.right(_)),
              E.map(_1 =>
                E.fromPredicate(
                  FormatValue => !FormatValue || FormatValue === ISSUER_FORMAT,
                  () =>
                    new Error("Format attribute of Issuer element is invalid")
                )(_1)
              ),
              E.map(() => E.right(_)),
              E.toUnion
            )
          )
        )
      ),
      TE.map(() => _)
    );

  const assertionIssuerValidationStep = (
    _: IIssueInstantWithAuthnContextCR
  ): TaskEither<Error, IIssueInstantWithAuthnContextCR> =>
    pipe(
      TE.fromEither(
        pipe(
          validateIssuer(_.Assertion, _.SAMLRequestCache.idpIssuer),
          E.chain(Issuer =>
            pipe(
              NonEmptyString.decode(Issuer.getAttribute("Format")),
              E.mapLeft(
                () =>
                  new Error(
                    "Format attribute of Issuer element must be a non empty string into Assertion"
                  )
              ),
              E.chain(
                E.fromPredicate(
                  Format => Format === ISSUER_FORMAT,
                  () =>
                    new Error("Format attribute of Issuer element is invalid")
                )
              ),
              E.fold(
                err =>
                  // Skip Issuer Format validation if IDP has non-strict validation option
                  !hasStrictValidation ? E.right(_) : E.left(err),
                _1 => E.right(_)
              )
            )
          )
        )
      ),
      TE.map(() => _)
    );

  const transformValidationStep = (
    _: IIssueInstantWithAuthnContextCR
  ): TaskEither<ITransformValidation, IIssueInstantWithAuthnContextCR> =>
    pipe(
      TE.fromEither(
        transformsValidation(_.Response, _.SAMLRequestCache.idpIssuer)
      ),
      TE.map(() => _)
    );

  const validationFailure = (error: Error | ITransformValidation): void => {
    if (eventHandler) {
      TransformError.is(error)
        ? eventHandler({
            data: {
              idpIssuer: error.idpIssuer,
              message: error.message,
              numberOfTransforms: String(error.numberOfTransforms)
            },
            name: "spid.error.transformOccurenceOverflow",
            type: "ERROR"
          })
        : eventHandler({
            data: {
              message: error.message
            },
            name: "spid.error.generic",
            type: "ERROR"
          });
    }
    return callback(E.toError(error.message));
  };

  const validationSuccess = (_: IIssueInstantWithAuthnContextCR): void => {
    // Number of the Response signature.
    // Calculated as number of the Signature elements inside the document minus number of the Signature element of the Assertion.
    const signatureOfResponseCount =
      _.Response.getElementsByTagNameNS(SAML_NAMESPACE.XMLDSIG, "Signature")
        .length -
      _.Assertion.getElementsByTagNameNS(SAML_NAMESPACE.XMLDSIG, "Signature")
        .length;
    // For security reasons it is preferable that the Response be signed.
    // According to the technical rules of SPID, the signature of the Response is optional @ref https://docs.italia.it/italia/spid/spid-regole-tecniche/it/stabile/single-sign-on.html#response.
    // Here we collect data when an IDP sends an unsigned Response.
    // If all IDPs sign it, we can safely request it as mandatory @ref https://www.pivotaltracker.com/story/show/174710289.
    if (eventHandler && signatureOfResponseCount === 0) {
      eventHandler({
        data: {
          idpIssuer: _.SAMLRequestCache.idpIssuer,
          message: "Missing Request signature"
        },
        name: "spid.error.signature",
        type: "INFO"
      });
    }
    return callback(null, true, _.InResponseTo);
  };

  return pipe(
    responseElementValidationStep,
    TE.chain(returnRequestAndResponseStep),
    TE.chain(parseSAMLRequestStep),
    TE.chain(getIssueInstantFromRequestStep),
    TE.chain(issueInstantValidationStep),
    TE.chain(assertionIssueInstantValidationStep),
    TE.chain(authnContextClassRefValidationStep),
    TE.chain(attributesValidationStep),
    TE.chain(responseIssuerValidationStep),
    TE.chain(assertionIssuerValidationStep),
    TE.chainW(transformValidationStep),
    TE.bimap(validationFailure, validationSuccess)
  )().catch(callback);
};
