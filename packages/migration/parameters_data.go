/*---------------------------------------------------------------------------------------------
 *  Copyright (c) IBAX. All rights reserved.
 *  See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

package migration

var parametersDataSQL = `
INSERT INTO "1_parameters" ("id","name", "value", "conditions", "ecosystem") VALUES
	(next_id('1_parameters'),'founder_account', '{{.Wallet}}', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'new_table', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_tables', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_language', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_page', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_menu', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_contracts', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_parameters', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_app_params', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'max_sum', '1000000', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'stylesheet', 'body {
		  /* You can define your custom styles here or create custom CSS rules */
	}', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'print_stylesheet', 'body {
		  /* You can define your custom styles here or create custom CSS rules */
	}', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'max_tx_block_per_user', '1000', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'min_page_validate_count', '1', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'max_page_validate_count', '6', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}'),
	(next_id('1_parameters'),'changing_blocks', 'ContractConditions("MainCondition")', 'ContractConditions("DeveloperCondition")', '{{.Ecosystem}}');
`
    (next_id('1_parameters'),'private_round_balance', '63000000000000000000', 'ContractConditions("@1DeveloperCondition")', '{{.Ecosystem}}'),
    (next_id('1_parameters'),'public_round_balance', '105000000000000000000', 'ContractConditions("@1DeveloperCondition")', '{{.Ecosystem}}'),
    (next_id('1_parameters'),'research_team_balance', '315000000000000000000', 'ContractConditions("@1DeveloperCondition")', '{{.Ecosystem}}'),
    (next_id('1_parameters'),'ecosystem_partners_balance', '168000000000000000000', 'ContractConditions("@1DeveloperCondition")', '{{.Ecosystem}}');
`
