# Personal Financial Master Plan Workbook

This repository now includes an automated `openpyxl` generator for a comprehensive financial planning workbook:

- **Workbook output:** `Personal Financial Master Plan.xlsx`
- **Generator script:** `scripts/generate_financial_workbook.py`
- **Validation script:** `scripts/recalc.py`

## Quick Start

```bash
python3 -m pip install openpyxl
python3 scripts/generate_financial_workbook.py
python3 scripts/recalc.py
```

If successful, `scripts/recalc.py` prints `status: success`.

## Sheet Navigation Map (22 sheets in order)

1. Master Data  
2. Dashboard  
3. Paycheck Calculator  
4. Tax Planning  
5. Income  
6. Budget  
7. Debt Tracker  
8. Debt Payoff Strategy  
9. Emergency Fund Analysis  
10. Child Support Projection  
11. Debt vs Investment Analysis  
12. 200K Allocation Plan  
13. Tax-Optimized Savings Strategy  
14. Cash Flow Waterfall  
15. Scenario Modeling  
16. Retirement Planner  
17. Investment Allocation Tracker  
18. Child Support Impact Analysis  
19. Net Worth Statement  
20. Monthly Update Checklist  
21. Settings  
22. Tax Assumptions

## Monthly Update Instructions

1. Update recurring input data in **Master Data**.
2. Enter paycheck and withholding details in **Paycheck Calculator**.
3. Enter current-month expenses in **Budget**.
4. Update balances in **Debt Tracker**, **Emergency Fund Analysis**, and **Net Worth Statement**.
5. Review retirement projection and scenario outputs in **Retirement Planner** and **Scenario Modeling**.
6. Track task completion in **Monthly Update Checklist**.

## Notes

- All assumption cells in **Settings** are highlighted for annual review.
- Core data validations and conditional formatting rules are applied programmatically.
- Named ranges are defined to simplify cross-sheet formulas.
