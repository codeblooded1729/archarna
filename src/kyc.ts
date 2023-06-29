/** KYC_INF */
export type kyc_info = {
    /** NAME */
    name: string,
    /** DUI */
    derived_user_identifier: bigint,
    /** MK_LOC */
    merkle_tree_location: number,
}

/** The KYC entity */
export class KYC {
    /** KYC_INF_LIST */
    kyc_info_lis: kyc_info[];

    constructor() {
        this.kyc_info_lis = [];
    }
    /**
     * Adds KYC information of a user into the list
     * @param data 
     */
    add_kyc(data: kyc_info): void {
        this.kyc_info_lis.push(data);
    }

    /**
     * 
     * @param derived_user_identifier 
     * @returns 
     */
    search_identity(derived_user_identifier: bigint): string {
        for(const kyc_info_i of this.kyc_info_lis) {
            if(kyc_info_i.derived_user_identifier == derived_user_identifier) {
                return kyc_info_i.name;
            }
        }
        return 'Not found';
    }
}