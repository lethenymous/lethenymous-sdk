// Reuse the frozen author's ProgramTest setup/proof helpers without editing
// Core. Remap their manifest-relative artifact paths to the sibling Core crate.
macro_rules! env {
    ("CARGO_MANIFEST_DIR") => {
        concat!(
            std::env!("CARGO_MANIFEST_DIR"),
            "/../../../zkCPMM/programs/zkcpmm"
        )
    };
    ($name:literal) => {
        std::env!($name)
    };
}
include!(concat!(
    std::env!("CARGO_MANIFEST_DIR"),
    "/../../../zkCPMM/programs/zkcpmm/tests/phase1_program.rs"
));

fn reaud_bridge(request: &serde_json::Value) -> serde_json::Value {
    let script =
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("../local-pending-reconciliation.mjs");
    let mut child = Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "SDK recovery bridge: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn reaud_settle(
    ctx: &mut ProgramTestContext,
    ix: Instruction,
    budget: u32,
    label: &str,
) -> String {
    let mut tx = Transaction::new_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(budget),
            ComputeBudgetInstruction::set_compute_unit_price(2),
            ix,
        ],
        Some(&ctx.payer.pubkey()),
    );
    tx.sign(
        &[&ctx.payer],
        ctx.banks_client.get_latest_blockhash().await.unwrap(),
    );
    let signature = tx.signatures[0].to_string();
    let result = ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap();
    println!(
        "REAUD_SBF_SETTLE {label} signature={signature} cu={}",
        result.metadata.unwrap().compute_units_consumed
    );
    result.result.unwrap();
    signature
}

async fn reaud_accounts(
    ctx: &mut ProgramTestContext,
    pool: Pubkey,
    tree: Pubkey,
    nullifiers: &[[u8; 32]],
) -> Vec<serde_json::Value> {
    use zkcpmm::state::archive::{directory_pda, page_pda};
    let mut addresses = vec![tree, directory_pda(&pool, 0).0];
    addresses.extend((0..16).map(|page| page_pda(&pool, 0, page).0));
    addresses.extend(
        nullifiers
            .iter()
            .map(|nf| Pubkey::find_program_address(&[b"spent", pool.as_ref(), nf], &ID).0),
    );
    let mut result = Vec::new();
    for key in addresses {
        if let Some(a) = ctx.banks_client.get_account(key).await.unwrap() {
            result.push(serde_json::json!({"address":key.to_string(),"owner":a.owner.to_string(),"data":encode_bytes(&a.data),"executable":a.executable,"lamports":a.lamports}));
        }
    }
    result
}

#[tokio::test]
async fn reaud_issued_then_consumed_outputs_restore_as_spent() {
    use zkcpmm::state::shielded::{root, SpentNullifier};
    let (mut ctx, _, a, b, pool, va, vb, lp, ua, ub) = initialized_setup().await;
    let (state, tree, ca, cb) = initialize_shielded_state(&mut ctx, pool, a, b).await;
    let payer = ctx.payer.pubkey();
    let seed = [77; 32];
    let keys = shielded_core::ShieldedKeys::from_seed(&seed);
    let note = shielded_core::Note::new(
        pool.to_bytes(),
        a.to_bytes(),
        6000,
        keys.owner_commitment(),
        [78; 32],
    )
    .unwrap();
    let shield_signature = reaud_settle(
        &mut ctx,
        shield_instruction(
            payer,
            pool,
            a,
            b,
            state,
            tree,
            ca,
            cb,
            ua,
            ub,
            ShieldedAsset::A,
            6000,
            keys.owner_commitment(),
            note.randomness,
        ),
        200_000,
        "reaud_shield",
    )
    .await;
    let encode = |n: &shielded_core::Note| serde_json::json!({"asset":Pubkey::new_from_array(n.asset).to_string(),"amount":n.amount.to_string(),"generation":"0","randomness":encode_bytes(&n.randomness),"commitment":encode_bytes(&n.commitment())});
    // Retain an actual pending shield journal BEFORE this note is consumed.
    let mut shield_request = serde_json::json!({"programId":ID.to_string(),"pool":pool.to_string(),"seed":encode_bytes(&seed),"kind":"shield","input":null,"outputs":[encode(&note)],"indices":["0"],"signature":shield_signature,"prepareOnly":true});
    let pending_shield = reaud_bridge(&shield_request);
    let input_data = ctx
        .banks_client
        .get_account(tree)
        .await
        .unwrap()
        .unwrap()
        .data;
    let input_tree = TreeState::try_deserialize(&mut input_data.as_slice()).unwrap();
    let input_path = sdk_archive_path(&mut ctx, &note, seed, 0, Some(0)).await;
    let reserve_in = token_amount(&mut ctx, va).await;
    let reserve_out = token_amount(&mut ctx, vb).await;
    let amount_out = swap_output(reserve_in, reserve_out, 2000, FEE).unwrap();
    let change = shielded_core::Note::new(
        pool.to_bytes(),
        a.to_bytes(),
        4000,
        keys.owner_commitment(),
        [79; 32],
    )
    .unwrap();
    let output = shielded_core::Note::new(
        pool.to_bytes(),
        b.to_bytes(),
        amount_out,
        keys.owner_commitment(),
        [80; 32],
    )
    .unwrap();
    let nf = shielded_core::nullifier(&keys, &note);
    let spent = Pubkey::find_program_address(&[b"spent", pool.as_ref(), &nf], &ID).0;
    let witness = zkcpmm_zk::private_swap::PrivateSwapWitness {
        public: zkcpmm_zk::private_swap::PrivateSwapPublicInputs {
            pool: pool.to_bytes(),
            asset_in: a.to_bytes(),
            asset_out: b.to_bytes(),
            root: root(&input_tree).unwrap(),
            root_sequence: input_tree.sequence,
            tree_generation: 0,
            nullifier: nf,
            reserve_in,
            reserve_out,
            fee_bps: FEE as u64,
            amount_in: 2000,
            amount_out,
            change_amount: 4000,
            change_commitment: change.commitment(),
            output_commitment: output.commitment(),
            direction: 0,
            swap_nonce: 0,
        },
        input_spend_secret: keys.spend_secret,
        input_randomness: note.randomness,
        path: input_path,
        change_spend_secret: keys.spend_secret,
        change_randomness: change.randomness,
        output_spend_secret: keys.spend_secret,
        output_randomness: output.randomness,
    };
    let (proof, _) = production_private_proof(&witness);
    let mut accounts = accounts::PrivateSwap {
        payer,
        pool,
        shielded_state: state,
        input_tree: tree,
        output_tree: tree,
        page_directory: zkcpmm::state::archive::directory_pda(&pool, 0).0,
        first_output_page: zkcpmm::state::archive::page_pda(&pool, 0, 0).0,
        token_a_mint: a,
        token_b_mint: b,
        lp_mint: lp,
        lp_vault_a: va,
        lp_vault_b: vb,
        protocol_fee_vault_a: protocol_fee_vault_a(pool),
        protocol_fee_vault_b: protocol_fee_vault_b(pool),
        creator_fee_vault_a: creator_fee_vault_a(pool),
        creator_fee_vault_b: creator_fee_vault_b(pool),
        custody_a: ca,
        custody_b: cb,
    }
    .to_account_metas(None);
    accounts[0].is_signer = true;
    accounts.extend([
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new(spent, false),
    ]);
    let ix = Instruction {
        program_id: ID,
        accounts,
        data: instruction::PrivateSwap {
            direction: zkcpmm::state::pool::Direction::AToB,
            root: root(&input_tree).unwrap(),
            root_sequence: input_tree.sequence,
            tree_generation: 0,
            nullifier: nf,
            amount_in: 2000,
            amount_out,
            change_amount: 4000,
            change_commitment: change.commitment(),
            output_commitment: output.commitment(),
            proof,
        }
        .data(),
    };
    let swap_signature = reaud_settle(&mut ctx, ix, 1_400_000, "private_swap_reaud").await;
    let change_nf = shielded_core::nullifier(&keys, &change);
    let output_nf = shielded_core::nullifier(&keys, &output);
    // Save the original pending swap journal before the later unshield. No
    // final locations/spent classifications are written to this encrypted file.
    let mut swap_request = serde_json::json!({"programId":ID.to_string(),"pool":pool.to_string(),"seed":encode_bytes(&seed),"kind":"private_swap","input":encode(&note),"outputs":[encode(&change),encode(&output)],"indices":["1","2"],"signature":swap_signature,"nullifier":encode_bytes(&nf),"prepareOnly":true});
    let pending_swap = reaud_bridge(&swap_request);
    let current_data = ctx
        .banks_client
        .get_account(tree)
        .await
        .unwrap()
        .unwrap()
        .data;
    let current = TreeState::try_deserialize(&mut current_data.as_slice()).unwrap();
    assert_eq!(current.next_index, 3);
    let change_path = sdk_archive_path(&mut ctx, &change, seed, 0, Some(1)).await;
    let w = zkcpmm_zk::shielded::ShieldedWitness::from_note(
        &keys,
        &change,
        change_path,
        root(&current).unwrap(),
        payer.to_bytes(),
    );
    let (proof, public_inputs) = production_unshield_proof(&w);
    let change_spent = Pubkey::find_program_address(&[b"spent", pool.as_ref(), &change_nf], &ID).0;
    reaud_settle(
        &mut ctx,
        Instruction {
            program_id: ID,
            accounts: accounts::Unshield {
                payer,
                pool,
                shielded_state: state,
                tree,
                token_a_mint: a,
                token_b_mint: b,
                custody_a: ca,
                custody_b: cb,
                recipient: payer,
                recipient_a: ua,
                recipient_b: ub,
                spent_nullifier: change_spent,
                token_program: spl_token::id(),
                system_program: solana_sdk::system_program::id(),
            }
            .to_account_metas(None),
            data: instruction::Unshield {
                asset: ShieldedAsset::A,
                root: root(&current).unwrap(),
                root_sequence: current.sequence,
                tree_generation: 0,
                amount: 4000,
                nullifier: change_nf,
                proof,
                public_inputs,
            }
            .data(),
        },
        500_000,
        "reaud_consume_change",
    )
    .await;
    for (key, expected_nf) in [(spent, nf), (change_spent, change_nf)] {
        let account = ctx.banks_client.get_account(key).await.unwrap().unwrap();
        assert_eq!(account.owner, ID);
        assert_eq!(account.data.len(), SpentNullifier::LEN);
        let record = SpentNullifier::try_deserialize(&mut account.data.as_slice()).unwrap();
        assert_eq!(record.pool, pool);
        assert_eq!(record.nullifier, expected_nf);
        assert_eq!(record.version, 1);
    }
    assert!(ctx
        .banks_client
        .get_account(Pubkey::find_program_address(&[b"spent", pool.as_ref(), &output_nf], &ID).0)
        .await
        .unwrap()
        .is_none());
    let canonical = reaud_accounts(&mut ctx, pool, tree, &[nf, change_nf, output_nf]).await;
    swap_request["prepareOnly"] = serde_json::json!(false);
    swap_request["journalDirectory"] = pending_swap["journalDirectory"].clone();
    swap_request["accounts"] = serde_json::json!(canonical);
    swap_request["consumedIndices"] = serde_json::json!([0]);
    let recovered_swap = reaud_bridge(&swap_request);
    assert_eq!(
        recovered_swap["recoveredStates"],
        serde_json::json!(["spent", "available"])
    );
    assert_eq!(recovered_swap["historyCalls"], 0);
    println!("REAUD_SBF_SWAP {recovered_swap}");
    shield_request["prepareOnly"] = serde_json::json!(false);
    shield_request["journalDirectory"] = pending_shield["journalDirectory"].clone();
    shield_request["accounts"] = serde_json::json!(canonical);
    shield_request["consumedIndices"] = serde_json::json!([0]);
    let recovered_shield = reaud_bridge(&shield_request);
    assert_eq!(
        recovered_shield["recoveredStates"],
        serde_json::json!(["spent"])
    );
    assert_eq!(recovered_shield["historyCalls"], 0);
    println!("REAUD_SBF_SHIELD {recovered_shield}");
}
