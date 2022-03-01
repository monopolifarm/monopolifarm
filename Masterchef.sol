// SPDX-License-Identifier: MIT
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
interface IStrategy {
    function wantLockedTotal() external view returns (uint256);
    function earn() external;
    function deposit(uint256 _wantAmt) external returns (uint256);
    function withdraw(uint256 _wantAmt) external returns (uint256);
}
interface IEarningsReferral {
    function recordReferral(address _user, address _referrer) external;
    function recordReferralCommission(address _referrer, uint256 _commission) external;
    function getReferrer(address _user) external view returns (address);
    function updateOperator(address _operator, bool _status) external;
}
abstract contract MintableToken is ERC20 {
    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }
}
pragma solidity 0.6.12;
contract Masterchef is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    struct UserInfo {
        uint256 amount; // How many amount tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 harvestLockTimestamp; // Harvest lock start timestamp.
    }

    struct PoolInfo {
        IERC20 want; // Address of the want token.
        uint256 allocPoint; // How many allocation points assigned to this pool. Earnings to distribute per second.
        uint256 lastRewardTimestamp; // Last timestamp that earnings distribution occurs.
        uint256 accEarningsPerShare; // Accumulated earnings per share, times 1e12. See below.
        address strat; // Strategy address that will earnings compound want tokens
        uint16 depositFeeBP;      // Deposit fee in basis points
    }

    address public earningToken;
    address public devaddr;
    address public feeAddr;
    address public constant burnAddress = 0x000000000000000000000000000000000000dEaD;

    uint256 public earningsPerSecond = 0.01 ether;
    uint256 public earningsDevPerSecond =  0.001 ether;
    uint256 public startTimestamp;
    uint256 public endTimestamp;
    uint256 public harvestLockInterval;  // harvest lock interval in seconds
    
    IEarningsReferral public earningReferral;
    uint16 public referralCommissionRate = 200;
    uint16 public constant MAXIMUM_REFERRAL_COMMISSION_RATE = 5000;

    PoolInfo[] public poolInfo; // Info of each pool.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo; // Info of each user that stakes LP tokens.
    uint256 public totalAllocPoint = 0; // Total allocation points. Must be the sum of all allocation points in all pools.
    
    uint256[] public withdrawalFeeIntervals = [1];
    uint16[] public withdrawalFeeBP = [0, 0];
    uint16 public constant MAX_WITHDRAWAL_FEE_BP = 300;
    uint16 public constant MAX_DEPOSIT_FEE_BP = 400;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event SetFeeAddress(address indexed user, address indexed newAddress);
    event SetDevAddress(address indexed user, address indexed newAddress);
    event ReferralCommissionPaid(address indexed user, address indexed referrer, uint256 commissionAmount);
    event NewEarningsEmission(uint256 earningsPerSecond);

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    constructor(
        address _devaddr,
        address _feeAddr,
        uint256 _startTimestamp,
        uint256 _endTimestamp,
        address _earningToken,
        uint256 _harvestLockInterval
    ) public {
        devaddr = _devaddr;
        feeAddr = _feeAddr;
        startTimestamp = _startTimestamp;
        endTimestamp = _endTimestamp;
        earningToken = _earningToken;
        harvestLockInterval = _harvestLockInterval;
    }

    modifier poolExists(uint256 pid) {
        require(pid < poolInfo.length, "pool inexistent");
        _;
    }

    function add(
        uint256 _allocPoint,
        IERC20 _want,
        bool _withUpdate,
        address _strat,
        uint16 _depositFeeBP
    ) public onlyOwner {
        require(_depositFeeBP <= MAX_DEPOSIT_FEE_BP, "add: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardTimestamp =
            block.timestamp > startTimestamp ? block.timestamp : startTimestamp;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolInfo.push(
            PoolInfo({
                want: _want,
                allocPoint: _allocPoint,
                lastRewardTimestamp: lastRewardTimestamp,
                accEarningsPerShare: 0,
                strat: _strat,
                depositFeeBP : _depositFeeBP
            })
        );
    }

    function set(
        uint256 _pid,
        uint256 _allocPoint,
        bool _withUpdate,
        uint16 _depositFeeBP
    ) public onlyOwner poolExists(_pid) {
        require(_depositFeeBP <= MAX_DEPOSIT_FEE_BP, "set: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(
            _allocPoint
        );
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
    }

    function getMultiplier(uint256 _from, uint256 _to)
        public
        view
        returns (uint256)
    {
        if (_from > _to)
            return 0;
        return _to.sub(_from);
    }

    function pendingEarnings(uint256 _pid, address _user)
        external
        view
        returns (uint256)
    {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accEarningsPerShare = pool.accEarningsPerShare;
        uint256 wantLockedTotal = IStrategy(pool.strat).wantLockedTotal();
        uint256 lastTimestamp = endTimestamp < block.timestamp ? endTimestamp : block.timestamp;
        if (lastTimestamp > pool.lastRewardTimestamp && wantLockedTotal != 0) {
            uint256 multiplier =
                getMultiplier(pool.lastRewardTimestamp, lastTimestamp);
            uint256 earningsReward =
                multiplier.mul(earningsPerSecond).mul(pool.allocPoint).div(
                    totalAllocPoint
                );
            accEarningsPerShare = accEarningsPerShare.add(
                earningsReward.mul(1e12).div(wantLockedTotal)
            );
        }
        return user.amount.mul(accEarningsPerShare).div(1e12).sub(user.rewardDebt);
    }

    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.timestamp <= pool.lastRewardTimestamp) {
            return;
        }
        uint256 lastTimestamp = endTimestamp < block.timestamp ? endTimestamp : block.timestamp;
        uint256 wantLockedTotal = IStrategy(pool.strat).wantLockedTotal();
        if (wantLockedTotal == 0) {
            pool.lastRewardTimestamp = lastTimestamp;
            return;
        }
        
        uint256 multiplier = getMultiplier(pool.lastRewardTimestamp, lastTimestamp);
        if (multiplier <= 0) {
            return;
        }
        uint256 earningsReward =  multiplier.mul(earningsPerSecond).mul(pool.allocPoint).div(totalAllocPoint);

        MintableToken(earningToken).mint(
            devaddr,
            multiplier.mul(earningsDevPerSecond).mul(pool.allocPoint).div(
                totalAllocPoint
            )
        );

        MintableToken(earningToken).mint(
            address(this),
            earningsReward
        );

        pool.accEarningsPerShare = pool.accEarningsPerShare.add(
            earningsReward.mul(1e12).div(wantLockedTotal)
        );
        pool.lastRewardTimestamp = lastTimestamp;
    }

    function deposit(uint256 _pid,uint256 _wantAmt, address _referrer) public nonReentrant poolExists(_pid){
        updatePool(_pid);
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        if (_wantAmt > 0 && address(earningReferral) != address(0) && _referrer != address(0) && _referrer != msg.sender) {
            earningReferral.recordReferral(msg.sender, _referrer);
        }
        if (user.amount > 0) {
            uint256 pending =
                user.amount.mul(pool.accEarningsPerShare).div(1e12).sub(
                    user.rewardDebt
                );
            uint256 harvestLockElapsed = block.timestamp - user.harvestLockTimestamp;
            if (pending > 0 && harvestLockElapsed > harvestLockInterval) {
                safeEarningsTransfer(msg.sender, pending);
                payReferralCommission(msg.sender, pending);
                user.harvestLockTimestamp = block.timestamp;
            }
        }
        if (_wantAmt > 0) {
            uint256 wantBalBefore = IERC20(pool.want).balanceOf(address(this));
            pool.want.safeTransferFrom(address(msg.sender), address(this), _wantAmt);
            uint256 wantBalAfter = IERC20(pool.want).balanceOf(address(this));
            _wantAmt = wantBalAfter.sub(wantBalBefore);
        
            uint256 amount = _wantAmt;
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _wantAmt.mul(pool.depositFeeBP).div(10000);
                pool.want.safeTransfer(feeAddr, depositFee);
                amount = (_wantAmt).sub(depositFee);
            }
            pool.want.safeIncreaseAllowance(pool.strat, amount);
            uint256 amountDeposit =
                IStrategy(poolInfo[_pid].strat).deposit(amount);
            user.amount = user.amount.add(amountDeposit);
            user.harvestLockTimestamp = block.timestamp;
        }
        user.rewardDebt = user.amount.mul(pool.accEarningsPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _wantAmt);
    }

    function withdraw(uint256 _pid, uint256 _wantAmt) public nonReentrant poolExists(_pid){
        updatePool(_pid);

        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        uint256 total = IStrategy(pool.strat).wantLockedTotal();

        require(user.amount > 0, "user.amount is 0");
        require(total > 0, "Total is 0");

        // Withdraw pending Earnings
        uint256 pending =
            user.amount.mul(pool.accEarningsPerShare).div(1e12).sub(
                user.rewardDebt
            );
            
        uint256 harvestLockElapsed = block.timestamp - user.harvestLockTimestamp;
        if (pending > 0 && harvestLockElapsed > harvestLockInterval) {
            safeEarningsTransfer(msg.sender, pending);
            payReferralCommission(msg.sender, pending);
            user.harvestLockTimestamp = block.timestamp;
        }

        uint256 amount = user.amount;
        if (_wantAmt > amount) {
            _wantAmt = amount;
        }
        if (_wantAmt > 0) {
            uint256 amountRemove =
                IStrategy(pool.strat).withdraw(_wantAmt);

            if (amountRemove > user.amount) {
                user.amount = 0;
            } else {
                user.amount = user.amount.sub(amountRemove);
            }

            uint256 wantBal = IERC20(pool.want).balanceOf(address(this));
            if (wantBal < _wantAmt) {
                _wantAmt = wantBal;
            }

            pool.want.safeTransfer(address(msg.sender), _wantAmt);
        }
        user.rewardDebt = user.amount.mul(pool.accEarningsPerShare).div(1e12);
        emit Withdraw(msg.sender, _pid, _wantAmt);
    }

    function emergencyWithdraw(uint256 _pid) public nonReentrant poolExists(_pid){
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        amount = IStrategy(pool.strat).withdraw(amount);
        user.amount = 0;
        user.rewardDebt = 0;
        pool.want.safeTransfer(address(msg.sender), amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    function safeEarningsTransfer(address _to, uint256 _EarningsAmt) internal {
        uint256 EarningsBal = IERC20(earningToken).balanceOf(address(this));
        if (_EarningsAmt > EarningsBal) {
            IERC20(earningToken).transfer(_to, EarningsBal);
        } else {
            IERC20(earningToken).transfer(_to, _EarningsAmt);
        }
    }

    function inCaseTokensGetStuck(address _token, uint256 _amount)
        public
        onlyOwner
    {
        require(_token != earningToken, "!safe");
        IERC20(_token).safeTransfer(msg.sender, _amount);
    }

    function setDevAddress(address _devaddr) public onlyOwner {
        devaddr = _devaddr;
        emit SetDevAddress(msg.sender, _devaddr);
    }

    function setFeeAddress(address _feeAddress) public onlyOwner {
        feeAddr = _feeAddress;
        emit SetFeeAddress(msg.sender, _feeAddress);
    }
    
    function setEarningsReferral(IEarningsReferral _earningReferral) public onlyOwner {
        earningReferral = _earningReferral;
    }

    function setReferralCommissionRate(uint16 _referralCommissionRate) public onlyOwner {
        require(_referralCommissionRate <= MAXIMUM_REFERRAL_COMMISSION_RATE, "setReferralCommissionRate: invalid referral commission rate basis points");
        referralCommissionRate = _referralCommissionRate;
    }

    function payReferralCommission(address _user, uint256 _pending) internal {
        if (address(earningReferral) != address(0) && referralCommissionRate > 0) {
            address referrer = earningReferral.getReferrer(_user);
            uint256 commissionAmount = _pending.mul(referralCommissionRate).div(10000);
            if (referrer != address(0) && commissionAmount > 0) {
                MintableToken(earningToken).mint(referrer, commissionAmount);
                earningReferral.recordReferralCommission(referrer, commissionAmount);
                emit ReferralCommissionPaid(_user, referrer, commissionAmount);
            }
        }
    }
    
    function transferEarningTokenOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        Ownable(earningToken).transferOwnership(newOwner);
    }
    
    function setEarningsPerSecond(uint256 _earningsPerSecond) external onlyOwner {
      earningsPerSecond = _earningsPerSecond;
      earningsDevPerSecond = _earningsPerSecond.div(10);
      emit NewEarningsEmission(_earningsPerSecond);
    }
    
    function setStartTimestamp(uint256 _startTimestamp) external onlyOwner {
        require(block.timestamp < startTimestamp, 'setStartTimestamp: The farming has already started');
        require(block.timestamp < _startTimestamp, 'setStartTimestamp: _startTimestamp must be larger than now');
        require(_startTimestamp < endTimestamp, 'setStartTimestamp: _startTimestamp must be smaller than endTimestamp');
        startTimestamp = _startTimestamp;
    }
    
    function setEndTimestamp(uint256 _endTimestamp) external onlyOwner {
        require(startTimestamp < _endTimestamp, 'setEndTimestamp: _endTimestamp must be larger than startTimestamp');
        require(block.timestamp < _endTimestamp, 'setEndTimestamp: _endTimestamp must be larger than now');
        endTimestamp = _endTimestamp;
    }
}
