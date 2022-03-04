
export const isIAcsUser = (obj: unknown): obj is IAcsUser => {
    if (typeof obj !== "object" || obj == null) return false;

    const objKeys = Object.keys(obj);

    return objKeys.some(k => k === "inResponseTo" /*"sessionIndex"*/);
}
  
export interface IAcsUser {
    issuer: string,
    inResponseTo: string,
    sessionIndex: string,
    nameID: string,
    nameIDFormat: string,
    nameQualifier: string,
    name: string,
    familyName: string,
    fiscalNumber: string,
    idCard: string,
    mobilePhone: string,
    email: string,
    address: string,
    domicileStreetAddress: string,
    domicilePostalCode: string,
    domicileMunicipality: string,
    domicileProvince: string,
    domicileNation: string
}
