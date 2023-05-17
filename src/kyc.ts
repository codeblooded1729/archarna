export type kyc_info = {
    name: string,
    derived_user_identifier: bigint,
    merkle_tree_location: number,
}

export class KYC {
    kyc_info_lis: kyc_info[];

    constructor() {
        this.kyc_info_lis = [];
    }

    add_kyc(data: kyc_info): void {
        this.kyc_info_lis.push(data);
    }

    search_identity(derived_user_identifier: bigint): string {
        for(const kyc_info_i of this.kyc_info_lis) {
            if(kyc_info_i.derived_user_identifier == derived_user_identifier) {
                return kyc_info_i.name;
            }
        }
        return 'Not found';
    }
}