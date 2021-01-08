# Fiat filter pallet 

- Support an extrinsic which takes a call to execute and deduct fees according to fiat price. It can also be used to allow only certain kinds of transactions.
- Compute fees according to fiat/token pair and deduct fees using `Currency::withdraw`. After executing, return `Pays:No` in `PostDispatchInfo`.
- The weight computation should take into account the weight of the call being passed by using its `dispatch_info`
- Use the `BaseCallFilter` in runtime lib.rs to disallow direct access to modules like DID, Blob, etc.
- Optional: Make the filter only accept calls to DID, Blob, etc pallet. Better option is to keep the pallet decoupled and accept the
`Call` types in configuration trait but this seems tricky as would i how would i accept an unbounded list of types.
- The default value of the pair fiat/token is set in genesis config.
- After each `n` blocks (configurable), calls a price update function. It doesn't request price from the contract
directly (by sending update price request to contract) to keep it decoupled from the pricing logic. The update function should
be configurable in the pallet's config trait, like `OnNewAccount` in `frame_system` pallet or `OnTransactionPayment` in transaction
payment pallet or `Slash` in democracy pallet. Have an implementation for `()` that does nothing. A price update function will be defined
in the contract (or supporting pallet) which will return the price.
- The default value of `n` is set in genesis.
- Supports another extrinsic to support changing the update frequency through Root.
- Support setting the value of fiat/token directly through Root (in case of an emergency)
- The price for DID write, update/remove (depending on key type), revoke/unrevoke (depending on number of items), blob (depending on byte size)
will be defined as constants in config trait, meaning updating them would require a runtime upgrade. Assume fiat amount will be given in 
  smallest unit like cents so use an integer type.

_For starting, i suggest not worrying about defining the update price function and build the capability where DID, revoke, etc
calls can be made through this pallet and the fees is computed using the price for fiat/token in genesis. Then compare the fees
with calling the actual DID, etc, modules. Then disable direct calling of the modules_